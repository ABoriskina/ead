package main

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

const (
	analyzerIP   = "127.0.0.1"
	analyzerPort = 9000
)

var analyzerConn net.Conn

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
	address := fmt.Sprintf("%s:%d", analyzerIP, analyzerPort)

	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("connect analyzer: %w", err)
	}

	analyzerConn = conn
	fmt.Printf("Connected to analyzer %s:%d\n", analyzerIP, analyzerPort)

	return nil
}

func newAnalyzerEvent(header eventsHeader, category, operation string) analyzerEvent {
	return analyzerEvent{
		Timestamp: getTimestamp(),
		EventType: category,
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
		},
	}
}

func sendEventToAnalyzer(data interface{}, eventType eventType) error {
	if analyzerConn == nil {
		return nil
	}

	var event analyzerEvent

	switch eventType {
	case eventConnect:
		e, ok := data.(*tcpConnectionEvent)
		if !ok {
			return fmt.Errorf("eventConnect: unexpected data type %T", data)
		}

		event = newAnalyzerEvent(e.Header, "network", "connect")
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

		event = newAnalyzerEvent(e.Header, "userspace", "execution")
		event.Event["fd"] = e.Fd
		event.Event["flags"] = e.Flags
		event.Event["pathname"] = cString(e.Pathname[:])
		event.Event["argv"] = cString(e.Argv[0][:])

	case eventOpenatExit:
		e, ok := data.(*openingEvent)
		if !ok {
			return fmt.Errorf("eventOpenatExit: unexpected data type %T", data)
		}

		event = newAnalyzerEvent(e.Header, "userspace", "opening")
		addOpeningFields(event.Event, e)
		event.Event["duration_ns"] = e.DurationNs

	case eventRenameExit:
		e, ok := data.(*renamingEvent)
		if !ok {
			return fmt.Errorf("eventRenameExit: unexpected data type %T", data)
		}

		event = newAnalyzerEvent(e.Header, "userspace", "renaming")
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

		event = newAnalyzerEvent(e.Header, "userspace", "fchmod")
		addOpeningFields(event.Event, e)

	case eventUnlinkExit:
		e, ok := data.(*unlinkingEvent)
		if !ok {
			return fmt.Errorf("eventUnlinkExit: unexpected data type %T", data)
		}

		event = newAnalyzerEvent(e.Header, "userspace", "unlink")
		event.Event["pathname"] = cString(e.Pathname[:])
		event.Event["fd"] = e.Fd
		event.Event["flags"] = e.Flags

	case eventCloneExit:
		e, ok := data.(*cloningEvent)
		if !ok {
			return fmt.Errorf("eventCloneExit: unexpected data type %T", data)
		}

		event = newAnalyzerEvent(e.Header, "userspace", "clone")
		event.Event["clone_flags"] = e.Flags
		event.Event["stack"] = e.Stack
		event.Event["stack_size"] = e.StackSize
		event.Event["parent_tid"] = e.ParentTid
		event.Event["child_tid"] = e.ChildTid
		event.Event["tls"] = e.Tls
		event.Event["exit_signal"] = e.ExitSignal

	default:
		return fmt.Errorf("unsupported analyzer event type: %d", eventType)
	}

	return sendAnalyzerEvent(event)
}

func addOpeningFields(event map[string]interface{}, e *openingEvent) {
	event["pathname"] = cString(e.Pathname[:])
	event["fd"] = e.Dirfd
	event["flags"] = e.Flags
	event["mode"] = e.Mode
}

func sendAnalyzerEvent(event analyzerEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal analyzer event: %w", err)
	}

	data = append(data, '\n')
	if _, err := analyzerConn.Write(data); err != nil {
		analyzerConn.Close()
		analyzerConn = nil

		return fmt.Errorf("send analyzer event: %w", err)
	}

	return nil
}
