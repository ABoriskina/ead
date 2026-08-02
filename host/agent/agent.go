package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	taskCommLen = 16
	maxPathLen  = 256
	maxArgLen   = 64
	maxArgs     = 3
)

type eventType uint32

const (
	eventExecve eventType = iota
	eventExecveExit

	eventConnect

	eventOpenat
	eventOpenatExit

	eventRename
	eventRenameExit

	eventChmod
	eventChmodExit

	eventFchmod
	eventFchmodExit

	eventUnlink
	eventUnlinkExit

	eventClone
	eventCloneExit
)

type eventsHeader struct {
	Type eventType
	Pid  uint32
	Tid  uint32
	Uid  uint32

	TimestampNs uint64
	Res         int64
	SyscallType uint32

	Comm [taskCommLen]byte

	_ uint32
}

type tcpConnectionEvent struct {
	Header eventsHeader

	Saddr uint32
	Daddr uint32

	Sport uint16
	Dport uint16
}

type executionEvent struct {
	Header eventsHeader

	Fd    int32
	Flags uint32

	Pathname [maxPathLen]byte
	Argv     [maxArgs][maxArgLen]byte
}

type openingEvent struct {
	Header   eventsHeader
	Pathname [maxPathLen]byte
	Dirfd    int32
	Fd       int32
	Flags    uint32
	Mode     uint32
	_        uint32

	DurationNs uint64
}

type renamingEvent struct {
	Header  eventsHeader
	Oldname [maxPathLen]byte
	Newname [maxPathLen]byte

	Olddirfd int32
	Newdirfd int32
	Flags    uint32
}

type unlinkingEvent struct {
	Header   eventsHeader
	Pathname [maxPathLen]byte
	Fd       int32
	Flags    uint32
}

type cloningEvent struct {
	Header eventsHeader

	Flags         uint64
	Stack         uint64
	StackSize     uint64
	ParentTid     uint64
	ChildTid      uint64
	CreatedTaskID int32
	_             uint32
	Tls           uint64
	ExitSignal    uint64
}

const (
	configEventTCP uint32 = 1 << iota
	configEventOpen
	configEventExecve
	configEventRename
	configEventFchmod
	configEventUnlink
	configEventClone
)

type bpfCollectorConfig struct {
	EnabledEvents    uint32
	SuccessfulEvents uint32

	OpenWriteOnly uint8

	Reserved [3]uint8
}

var agentConfig config

type pathOption int

const (
	includePath pathOption = iota
	excludePath
)

func bytesToString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}

	return string(buf)
}

func pathHasPrefix(pathname string, prefix string) bool {
	return strings.HasPrefix(pathname, prefix)
}

func pathInList(pathname string, filter *eventFilterConfig, option pathOption) bool {
	switch option {
	case includePath:
		for _, path := range filter.IncludePaths {
			if pathHasPrefix(pathname, path) {
				return true
			}
		}

	case excludePath:
		for _, path := range filter.ExcludePaths {
			if pathHasPrefix(pathname, path) {
				return true
			}
		}
	}

	return false
}

func checkPath(pathname string, filter *eventFilterConfig) bool {
	if filter.FollowAll {
		return true
	}

	if filter.FollowOnlyInclude {
		return pathInList(pathname, filter, includePath)
	} else if filter.FollowOnlyExclude {
		return !pathInList(pathname, filter, excludePath)
	}

	return true
}

func prepareBPFConfig(cfg *config) bpfCollectorConfig {
	var bpfConfig bpfCollectorConfig

	if cfg.Events.TCP {
		bpfConfig.EnabledEvents |= configEventTCP
	}

	if cfg.Events.Open {
		bpfConfig.EnabledEvents |= configEventOpen
	}

	if cfg.Events.Execve {
		bpfConfig.EnabledEvents |= configEventExecve
	}

	if cfg.Events.Rename {
		bpfConfig.EnabledEvents |= configEventRename
	}

	if cfg.Events.Chmod {
		bpfConfig.EnabledEvents |= configEventFchmod
	}

	if cfg.Events.Unlink {
		bpfConfig.EnabledEvents |= configEventUnlink
	}

	if cfg.Events.Clone {
		bpfConfig.EnabledEvents |= configEventClone
	}

	if cfg.Filters.SuccessfulOnly || cfg.Filters.TCP.SuccessfulOnly {
		bpfConfig.SuccessfulEvents |= configEventTCP
	}
	if cfg.Filters.SuccessfulOnly || cfg.Filters.Open.SuccessfulOnly {
		bpfConfig.SuccessfulEvents |= configEventOpen
	}
	if cfg.Filters.SuccessfulOnly || cfg.Filters.Execve.SuccessfulOnly {
		bpfConfig.SuccessfulEvents |= configEventExecve
	}
	if cfg.Filters.SuccessfulOnly || cfg.Filters.Rename.SuccessfulOnly {
		bpfConfig.SuccessfulEvents |= configEventRename
	}
	if cfg.Filters.SuccessfulOnly || cfg.Filters.Chmod.SuccessfulOnly {
		bpfConfig.SuccessfulEvents |= configEventFchmod
	}
	if cfg.Filters.SuccessfulOnly || cfg.Filters.Unlink.SuccessfulOnly {
		bpfConfig.SuccessfulEvents |= configEventUnlink
	}
	if cfg.Filters.SuccessfulOnly || cfg.Filters.Clone.SuccessfulOnly {
		bpfConfig.SuccessfulEvents |= configEventClone
	}

	if cfg.Filters.Open.WriteOnly {
		bpfConfig.OpenWriteOnly = 1
	}

	return bpfConfig
}

func resolveFDPath(pid uint32, fd int32) (string, error) {
	procPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)

	path, err := os.Readlink(procPath)
	if err != nil {
		return "", err
	}

	return path, nil
}

func resolveProcessPath(pid uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}

func resolveEventPath(pid uint32, dirfd int32, pathname string) (string, error) {
	if pathname == "" {
		if dirfd >= 0 {
			return resolveFDPath(pid, dirfd)
		}

		return "", fmt.Errorf("cannot resolve empty pathname")
	}

	if filepath.IsAbs(pathname) {
		return pathname, nil
	}

	var basePath string
	var err error

	if dirfd == unix.AT_FDCWD {
		procPath := fmt.Sprintf("/proc/%d/cwd", pid)

		basePath, err = os.Readlink(procPath)
		if err != nil {
			return "", err
		}
	} else if dirfd >= 0 {
		basePath, err = resolveFDPath(pid, dirfd)
		if err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("invalid dirfd: %d", dirfd)
	}

	return filepath.Join(basePath, pathname), nil
}

func main() {
	if err := parseConfig(&agentConfig); err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("collector.bpf.o")
	if err != nil {
		log.Fatalf("failed to open BPF object: %v", err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to load BPF object: %v", err)
	}
	defer collection.Close()

	configMap, ok := collection.Maps["config_map"]
	if !ok {
		log.Fatal("failed to find config_map")
	}

	bpfConfig := prepareBPFConfig(&agentConfig)

	var key uint32

	if err := configMap.Put(key, bpfConfig); err != nil {
		log.Fatalf("failed to update config_map: %v", err)
	}

	links, err := attachPrograms(spec, collection)
	if err != nil {
		log.Fatalf("failed to attach BPF programs: %v", err)
	}

	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	eventsMap, ok := collection.Maps["events"]
	if !ok {
		log.Fatal("failed to find events map")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		log.Fatalf("failed to create ring buffer: %v", err)
	}
	defer reader.Close()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signals
		reader.Close()
	}()

	if err := connectToAnalyzer(); err != nil {
		log.Printf("failed to connect to analyzer: %v", err)
	}

	defer func() {
		if analyzerConn != nil {
			analyzerConn.Close()
		}
	}()

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}

			log.Printf("failed to read ring buffer: %v", err)
			continue
		}

		if err := handleEvent(record.RawSample); err != nil {
			log.Printf("failed to handle event: %v", err)
		}
	}
}

func handleEvent(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("event is too small")
	}

	eventType := eventType(binary.LittleEndian.Uint32(data[:4]))

	switch eventType {
	case eventConnect:
		var event tcpConnectionEvent

		if err := binary.Read(
			bytes.NewReader(data),
			binary.LittleEndian,
			&event,
		); err != nil {
			return err
		}

		pathname, err := resolveProcessPath(event.Header.Pid)
		if err != nil {
			pathname = "<unresolved>"
		}
		if !checkPath(pathname, &agentConfig.Filters.TCP) {
			return nil
		}

		srcIP := uint32ToIPv4(event.Saddr)
		dstIP := uint32ToIPv4(event.Daddr)

		fmt.Printf(
			"[EVENT_CONNECT] pid=%d comm=%s %s:%d -> %s:%d\n",
			event.Header.Pid,
			cString(event.Header.Comm[:]),
			srcIP,
			event.Sport,
			dstIP,
			event.Dport,
		)

		if err := sendEventToAnalyzer(&event, eventConnect); err != nil {
			log.Printf("failed to send connect event to analyzer: %v", err)
		}

	case eventExecveExit:
		var event executionEvent

		if err := binary.Read(
			bytes.NewReader(data),
			binary.LittleEndian,
			&event,
		); err != nil {
			return err
		}

		pathname := cString(event.Pathname[:])

		if !checkPath(pathname, &agentConfig.Filters.Execve) {
			return nil
		}

		fmt.Printf(
			"[EVENT_EXECVE] pid=%d uid=%d comm=%s file=%s argv0=%s argv1=%s argv2=%s\n",
			event.Header.Pid,
			event.Header.Uid,
			cString(event.Header.Comm[:]),
			pathname,
			cString(event.Argv[0][:]),
			cString(event.Argv[1][:]),
			cString(event.Argv[2][:]),
		)

		if err := sendEventToAnalyzer(&event, eventExecveExit); err != nil {
			log.Printf("failed to send execve event to analyzer: %v", err)
		}

	case eventOpenatExit:
		var event openingEvent

		if err := binary.Read(
			bytes.NewReader(data),
			binary.LittleEndian,
			&event,
		); err != nil {
			return err
		}

		pathname := cString(event.Pathname[:])

		if !checkPath(pathname, &agentConfig.Filters.Open) {
			return nil
		}

		fmt.Printf(
			"[EVENT_OPENAT] pid=%d uid=%d comm=%s file=%s dirfd=%d flags=%d mode=%d res=%d duration=%d\n",
			event.Header.Pid,
			event.Header.Uid,
			cString(event.Header.Comm[:]),
			pathname,
			event.Dirfd,
			event.Flags,
			event.Mode,
			event.Header.Res,
			event.DurationNs,
		)

		if err := sendEventToAnalyzer(&event, eventOpenatExit); err != nil {
			log.Printf("failed to send openat event to analyzer: %v", err)
		}

	case eventRenameExit:
		var event renamingEvent

		if err := binary.Read(
			bytes.NewReader(data),
			binary.LittleEndian,
			&event,
		); err != nil {
			return err
		}

		oldname := cString(event.Oldname[:])
		newname := cString(event.Newname[:])
		if !checkPath(oldname, &agentConfig.Filters.Rename) &&
			!checkPath(newname, &agentConfig.Filters.Rename) {
			return nil
		}

		// TODO: too much noise
		fmt.Printf(
			"[EVENT_RENAME] pid=%d uid=%d comm=%s oldname=%s newname=%s olddirfd=%d newdirfd=%d flags=%d syscall_type=%d res=%d\n",
			event.Header.Pid,
			event.Header.Uid,
			cString(event.Header.Comm[:]),
			cString(event.Oldname[:]),
			cString(event.Newname[:]),
			event.Olddirfd,
			event.Newdirfd,
			event.Flags,
			event.Header.SyscallType,
			event.Header.Res,
		)

		if err := sendEventToAnalyzer(&event, eventRenameExit); err != nil {
			log.Printf("failed to send rename event to analyzer: %v", err)
		}

	case eventFchmodExit:
		var event openingEvent

		if err := binary.Read(
			bytes.NewReader(data),
			binary.LittleEndian,
			&event,
		); err != nil {
			return err
		}

		eventPathname := cString(event.Pathname[:])
		pathname, err := resolveEventPath(
			event.Header.Pid,
			event.Dirfd,
			eventPathname,
		)

		if err != nil {
			pathname = "<unresolved>"
		}

		if !checkPath(pathname, &agentConfig.Filters.Chmod) {
			return nil
		}

		fmt.Printf(
			"[EVENT_(F)CHMOD] pid=%d fd=%d file=%s mode=%04o res=%d\n",
			event.Header.Pid,
			event.Dirfd,
			pathname,
			event.Mode,
			event.Header.Res,
		)
		if err := sendEventToAnalyzer(&event, eventFchmodExit); err != nil {
			log.Printf("failed to send fchmod event to analyzer: %v", err)
		}

	case eventUnlinkExit:
		var event unlinkingEvent

		if err := binary.Read(
			bytes.NewReader(data),
			binary.LittleEndian,
			&event,
		); err != nil {
			return err
		}

		pathname := cString(event.Pathname[:])

		if !checkPath(pathname, &agentConfig.Filters.Unlink) {
			return nil
		}

		fmt.Printf(
			"[EVENT_UNLINK] pid=%d uid=%d comm=%s file=%s fd=%d flags=%d res=%d\n",
			event.Header.Pid,
			event.Header.Uid,
			cString(event.Header.Comm[:]),
			pathname,
			event.Fd,
			event.Flags,
			event.Header.Res,
		)
		if err := sendEventToAnalyzer(&event, eventUnlinkExit); err != nil {
			log.Printf("failed to send unlink event to analyzer: %v", err)
		}

	case eventCloneExit:
		var event cloningEvent

		if err := binary.Read(
			bytes.NewReader(data),
			binary.LittleEndian,
			&event,
		); err != nil {
			return err
		}

		pathname, err := resolveProcessPath(event.Header.Pid)
		if err != nil {
			pathname = "<unresolved>"
		}
		if !checkPath(pathname, &agentConfig.Filters.Clone) {
			return nil
		}

		fmt.Printf(
			"[EVENT_CLONE] pid=%d uid=%d comm=%s flags=0x%x stack=%d stack_size=%d parent_tid=%d child_tid=%d tls=%d exit_signal=%d res=%d\n",
			event.Header.Pid,
			event.Header.Uid,
			cString(event.Header.Comm[:]),
			event.Flags,
			event.Stack,
			event.StackSize,
			event.ParentTid,
			event.ChildTid,
			event.Tls,
			event.ExitSignal,
			event.Header.Res,
		)
		if err := sendEventToAnalyzer(&event, eventCloneExit); err != nil {
			log.Printf("failed to send clone event to analyzer: %v", err)
		}
	}

	return nil
}

func attachPrograms(
	spec *ebpf.CollectionSpec,
	collection *ebpf.Collection,
) ([]link.Link, error) {
	var links []link.Link

	for name, programSpec := range spec.Programs {
		program, ok := collection.Programs[name]
		if !ok {
			return nil, fmt.Errorf("program %s not found", name)
		}

		section := programSpec.SectionName

		switch {
		case strings.HasPrefix(section, "tracepoint/"):
			parts := strings.Split(section, "/")
			if len(parts) != 3 {
				return nil, fmt.Errorf("invalid tracepoint section: %s", section)
			}

			l, err := link.Tracepoint(
				parts[1],
				parts[2],
				program,
				nil,
			)
			if err != nil {
				return nil, fmt.Errorf("attach %s: %w", section, err)
			}

			links = append(links, l)

		case strings.HasPrefix(section, "kprobe/"):
			symbol := strings.TrimPrefix(section, "kprobe/")

			l, err := link.Kprobe(symbol, program, nil)
			if err != nil {
				return nil, fmt.Errorf("attach %s: %w", section, err)
			}

			links = append(links, l)

		case strings.HasPrefix(section, "kretprobe/"):
			symbol := strings.TrimPrefix(section, "kretprobe/")

			l, err := link.Kretprobe(symbol, program, nil)
			if err != nil {
				return nil, fmt.Errorf("attach %s: %w", section, err)
			}

			links = append(links, l)

		default:
			return nil, fmt.Errorf(
				"unsupported BPF section: %s",
				section,
			)
		}
	}

	return links, nil
}

func uint32ToIPv4(addr uint32) net.IP {
	return net.IPv4(
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24),
	)
}

func cString(data []byte) string {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		data = data[:i]
	}

	return string(data)
}
