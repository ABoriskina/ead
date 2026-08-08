package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	analyzerIP   = "127.0.0.1"
	analyzerPort = 9000
)

var (
	analyzerConn   net.Conn
	analyzerConnMu sync.Mutex
)

type analyzerProcess struct {
	Pid  uint32 `json:"pid"`
	Tid  uint32 `json:"tid"`
	Uid  uint32 `json:"uid"`
	Comm string `json:"comm"`
}

type analyzerEvent struct {
	Timestamp string                 `json:"timestamp"`
	EventType string                 `json:"event_type"`
	Sensor    string                 `json:"sensor"`
	Host      string                 `json:"host"`
	Process   analyzerProcess        `json:"process"`
	Event     map[string]interface{} `json:"event"`
}

func getTimestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
}

func connectToAnalyzer() error {
	analyzerConnMu.Lock()
	if analyzerConn != nil {
		analyzerConnMu.Unlock()
		return nil
	}
	analyzerConnMu.Unlock()

	address := fmt.Sprintf("%s:%d", analyzerIP, analyzerPort)

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect analyzer: %w", err)
	}

	analyzerConnMu.Lock()
	defer analyzerConnMu.Unlock()
	if analyzerConn != nil {
		conn.Close()
		return nil
	}

	analyzerConn = conn
	log.Printf("Connected to analyzer %s:%d\n", analyzerIP, analyzerPort)

	return nil
}

func startAnalyzerReconnect() {
	if err := connectToAnalyzer(); err != nil {
		log.Printf("Failed to connect to analyzer: %v; retrying in one minute\n", err)
	}

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			if err := connectToAnalyzer(); err != nil {
				log.Printf("Failed to connect to analyzer: %v; retrying in one minute\n", err)
			}
		}
	}()
}

func closeAnalyzerConnection() {
	analyzerConnMu.Lock()
	defer analyzerConnMu.Unlock()

	if analyzerConn != nil {
		analyzerConn.Close()
		analyzerConn = nil
	}
}

const (
	operationCreateProcess     = "CREATE_PROCESS"
	operationExecute           = "EXECUTE"
	operationOpenRead          = "OPEN_READ"
	operationOpenWrite         = "OPEN_WRITE"
	operationRename            = "RENAME"
	operationChangePermissions = "CHANGE_PERMISSIONS"
	operationDelete            = "DELETE"
	operationEstablish         = "ESTABLISH"
)

func newAnalyzerEvent(header eventsHeader, eventType, operation string) analyzerEvent {
	return analyzerEvent{
		Timestamp: getTimestamp(),
		EventType: eventType,
		Sensor:    "ebpf-anomaly-detector",
		Host:      "localhost",
		Process: analyzerProcess{
			Pid:  header.Pid,
			Tid:  header.Tid,
			Uid:  header.Uid,
			Comm: cString(header.Comm[:]),
		},
		Event: map[string]interface{}{
			"operation":    operation,
			"type":         header.Type,
			"syscall_type": header.SyscallType,
			"result":       header.Res,
			"success":      header.Res >= 0,
			"timestamp_ns": eventRealtimeTimestamp(header.TimestampNs),
		},
	}
}

func eventRealtimeTimestamp(timestampNs uint64) string {
	var realtime unix.Timespec
	var monotonic unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &realtime); err != nil {
		return strconv.FormatUint(timestampNs, 10)
	}
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic); err != nil {
		return strconv.FormatUint(timestampNs, 10)
	}

	realtimeNs := uint64(realtime.Sec)*uint64(time.Second) + uint64(realtime.Nsec)
	monotonicNs := uint64(monotonic.Sec)*uint64(time.Second) + uint64(monotonic.Nsec)
	return strconv.FormatUint(timestampNs+(realtimeNs-monotonicNs), 10)
}

func sendEventToAnalyzer(data interface{}, eventType eventType) error {
	var event analyzerEvent

	switch eventType {
	case eventConnect:
		e, ok := data.(*tcpConnectionEvent)
		if !ok {
			return fmt.Errorf("eventConnect: unexpected data type %T", data)
		}

		event = newAnalyzerEvent(e.Header, "EVENT_CONNECT", operationEstablish)
		event.Event["protocol"] = "TCP"
		event.Event["src_ip"] = uint32ToIPv4(e.Saddr).String()
		event.Event["src_port"] = e.Sport
		event.Event["dst_ip"] = uint32ToIPv4(e.Daddr).String()
		event.Event["dst_port"] = e.Dport

	case eventExecveExit:
		e, ok := data.(*executionEvent)
		if !ok {
			return fmt.Errorf("eventExecveExit: unexpected data type %T", data)
		}

		event = newAnalyzerEvent(e.Header, "EVENT_EXECVE", operationExecute)
		event.Event["fd"] = e.Fd
		event.Event["flags"] = e.Flags
		event.Event["pathname"] = cString(e.Pathname[:])
		event.Event["argv"] = cString(e.Argv[0][:])

	case eventOpenatExit:
		e, ok := data.(*openingEvent)
		if !ok {
			return fmt.Errorf("eventOpenatExit: unexpected data type %T", data)
		}

		operation := operationOpenRead
		if e.Flags&unix.O_ACCMODE == unix.O_WRONLY || e.Flags&unix.O_ACCMODE == unix.O_RDWR {
			operation = operationOpenWrite
		}
		event = newAnalyzerEvent(e.Header, "EVENT_OPENAT", operation)
		event.Event["pathname"] = cString(e.Pathname[:])
		event.Event["dirfd"] = e.Dirfd
		event.Event["flags"] = e.Flags
		event.Event["mode"] = e.Mode
		event.Event["duration_ns"] = e.DurationNs
		event.Event["is_create_requested"] = e.Flags&unix.O_CREAT != 0
		if e.Header.Res >= 0 {
			event.Event["fd"] = int32(e.Header.Res)
		}

	case eventRenameExit:
		e, ok := data.(*renamingEvent)
		if !ok {
			return fmt.Errorf("eventRenameExit: unexpected data type %T", data)
		}

		event = newAnalyzerEvent(e.Header, "EVENT_RENAME", operationRename)
		event.Event["oldname"] = cString(e.Oldname[:])
		event.Event["newname"] = cString(e.Newname[:])
		event.Event["olddirfd"] = e.Olddirfd
		event.Event["newdirfd"] = e.Newdirfd
		event.Event["flags"] = e.Flags

	case eventFchmodExit:
		e, ok := data.(*openingEvent)
		if !ok {
			return fmt.Errorf("eventFchmodExit: unexpected data type %T", data)
		}

		event = newAnalyzerEvent(e.Header, "EVENT_FCHMOD", operationChangePermissions)
		event.Event["pathname"] = cString(e.Pathname[:])
		event.Event["fd"] = e.Dirfd
		event.Event["flags"] = e.Flags
		event.Event["mode"] = e.Mode

	case eventUnlinkExit:
		e, ok := data.(*unlinkingEvent)
		if !ok {
			return fmt.Errorf("eventUnlinkExit: unexpected data type %T", data)
		}

		event = newAnalyzerEvent(e.Header, "EVENT_UNLINK", operationDelete)
		event.Event["pathname"] = cString(e.Pathname[:])
		event.Event["fd"] = e.Fd
		event.Event["flags"] = e.Flags

	case eventCloneExit:
		e, ok := data.(*cloningEvent)
		if !ok {
			return fmt.Errorf("eventCloneExit: unexpected data type %T", data)
		}

		event = newAnalyzerEvent(e.Header, "EVENT_CLONE", operationCreateProcess)
		event.Event["clone_flags"] = e.Flags
		event.Event["stack"] = e.Stack
		event.Event["stack_size"] = e.StackSize
		event.Event["parent_tid"] = e.ParentTid
		event.Event["child_tid"] = e.ChildTid
		event.Event["created_task_id"] = e.CreatedTaskID
		event.Event["tls"] = e.Tls
		event.Event["exit_signal"] = e.ExitSignal

	default:
		return fmt.Errorf("unsupported analyzer event type: %d", eventType)
	}

	return sendAnalyzerEvent(event)
}

func sendAnalyzerEvent(event analyzerEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal analyzer event: %w", err)
	}

	data = append(data, '\n')

	analyzerConnMu.Lock()
	defer analyzerConnMu.Unlock()
	if analyzerConn == nil {
		return nil
	}

	if _, err := analyzerConn.Write(data); err != nil {
		analyzerConn.Close()
		analyzerConn = nil

		return fmt.Errorf("send analyzer event: %w", err)
	}

	return nil
}
