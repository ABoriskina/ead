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
	"strconv"
	"strings"
	"syscall"

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

	eventClone
	eventUnlink
)

type eventsHeader struct {
	Type eventType
	Pid  uint32
	Uid  uint32

	_ uint32

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
	Flags    uint32
	Mode     uint32

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

func resolveFDPath(pid uint32, fd int32) (string, error) {
	procPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)

	path, err := os.Readlink(procPath)
	if err != nil {
		return "", err
	}

	return path, nil
}

func main() {
	if len(os.Args) != 2 {
		os.Exit(1)
	}

	portValue, err := strconv.ParseUint(os.Args[1], 10, 16)
	if err != nil {
		log.Fatalf("invalid port: %v", err)
	}

	port := uint16(portValue)

	spec, err := ebpf.LoadCollectionSpec("collector.bpf.o")
	if err != nil {
		log.Fatalf("failed to open BPF object: %v", err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to load BPF object: %v", err)
	}
	defer collection.Close()

	configMap, ok := collection.Maps["tcp_connection_config"]
	if !ok {
		log.Fatal("failed to find map tcp_connection_config")
	}

	var key uint32

	if err := configMap.Put(key, port); err != nil {
		log.Fatalf("failed to update tcp_connection_config: %v", err)
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

	fmt.Printf("Started on port %d\n", port)

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

		if err := sendTCPEventToAnalyzer(&event); err != nil {
			log.Printf("failed to send connect event to analyzer: %v", err)
		}

	case eventExecve:
		var event executionEvent

		if err := binary.Read(
			bytes.NewReader(data),
			binary.LittleEndian,
			&event,
		); err != nil {
			return err
		}

		fmt.Printf(
			"[EVENT_EXECVE] pid=%d uid=%d comm=%s file=%s argv0=%s argv1=%s argv2=%s\n",
			event.Header.Pid,
			event.Header.Uid,
			cString(event.Header.Comm[:]),
			cString(event.Pathname[:]),
			cString(event.Argv[0][:]),
			cString(event.Argv[1][:]),
			cString(event.Argv[2][:]),
		)

		if err := sendExecveEventToAnalyzer(&event); err != nil {
			log.Printf("failed to send execve event to analyzer: %v", err)
		}

	case eventOpenat: // TODELETE: Not used
		var event openingEvent

		if err := binary.Read(
			bytes.NewReader(data),
			binary.LittleEndian,
			&event,
		); err != nil {
			return err
		}

		// TODO: too much noise
		fmt.Printf(
			"[EVENT_OPENAT] pid=%d uid=%d comm=%s file=%s dirfd=%d flags=%d mode=%d\n",
			event.Header.Pid,
			event.Header.Uid,
			cString(event.Header.Comm[:]),
			cString(event.Pathname[:]),
			event.Dirfd,
			event.Flags,
			event.Mode,
		)

		if err := sendOpenatEventToAnalyzer(&event); err != nil {
			log.Printf("failed to send openat event to analyzer: %v", err)
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

		// TODO: too much noise
		fmt.Printf(
			"[EVENT_OPENAT] pid=%d uid=%d comm=%s file=%s dirfd=%d flags=%d mode=%d res=%d duration=%d\n",
			event.Header.Pid,
			event.Header.Uid,
			cString(event.Header.Comm[:]),
			cString(event.Pathname[:]),
			event.Dirfd,
			event.Flags,
			event.Mode,
			int64(event.Header.Res),
			event.DurationNs,
		)

		if err := sendOpenatEventToAnalyzer(&event); err != nil {
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

		if err := sendRenameEventToAnalyzer(&event); err != nil {
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

		pathname, err := resolveFDPath(
			event.Header.Pid,
			event.Dirfd,
		)

		if err == nil {
			fmt.Printf(
				"[EVENT_FCHMOD] pid=%d fd=%d file=%s mode=%04o res=%d\n",
				event.Header.Pid,
				event.Dirfd,
				pathname,
				event.Mode,
				event.Header.Res,
			)
		} else {
			fmt.Printf(
				"[EVENT_(F)CHMOD] pid=%d fd=%d file=<unresolved> mode=%04o res=%d\n",
				event.Header.Pid,
				event.Dirfd,
				event.Mode,
				event.Header.Res,
			)
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
