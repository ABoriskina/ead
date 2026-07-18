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
	Comm string `json:"comm"`
}

type analyzerFlow struct {
	State string `json:"state"`
}

type analyzerTCPEvent struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	Sensor    string `json:"sensor"`
	Host      string `json:"host"`
	Proto     string `json:"proto"`

	SrcIP    string `json:"src_ip"`
	SrcPort  uint16 `json:"src_port"`
	DestIP   string `json:"dest_ip"`
	DestPort uint16 `json:"dest_port"`

	Process analyzerProcess `json:"process"`
	Flow    analyzerFlow    `json:"flow"`
}

type analyzerExecveEvent struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	Sensor    string `json:"sensor"`
	Host      string `json:"host"`
	Proto     string `json:"proto"`

	Filename string `json:"filename"`
	Argv     string `json:"argv"`

	Process analyzerProcess `json:"process"`
	Flow    analyzerFlow    `json:"flow"`
}

type analyzerOpenatEvent struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	Sensor    string `json:"sensor"`
	Host      string `json:"host"`
	Proto     string `json:"proto"`

	Pathname   string `json:"pathname"`
	Dirfd      int32  `json:"dirfd"`
	Flags      uint32 `json:"flags"`
	Mode       uint32 `json:"mode"`
	Result     int64  `json:"result"`
	DurationNs uint64 `json:"duration_ns"`

	Process analyzerProcess `json:"process"`
	Flow    analyzerFlow    `json:"flow"`
}

func getTimestamp() string {
	return time.Now().
		UTC().
		Format("2006-01-02T15:04:05.000000Z")
}

func connectToAnalyzer() error {
	address := fmt.Sprintf("%s:%d", analyzerIP, analyzerPort)

	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("connect analyzer: %w", err)
	}

	analyzerConn = conn

	fmt.Printf(
		"Connected to analyzer %s:%d\n",
		analyzerIP,
		analyzerPort,
	)

	return nil
}

func sendTCPEventToAnalyzer(e *tcpConnectionEvent) error {
	if analyzerConn == nil {
		return nil
	}

	event := analyzerTCPEvent{
		Timestamp: getTimestamp(),
		EventType: "flow",
		Sensor:    "ebpf-anomaly-detector",
		Host:      "localhost",
		Proto:     "TCP",

		SrcIP:    uint32ToIPv4(e.Saddr).String(),
		SrcPort:  e.Sport,
		DestIP:   uint32ToIPv4(e.Daddr).String(),
		DestPort: e.Dport,

		Process: analyzerProcess{
			Pid:  e.Header.Pid,
			Comm: cString(e.Header.Comm[:]),
		},

		Flow: analyzerFlow{
			State: "established",
		},
	}

	return sendAnalyzerEvent(event)
}

func sendExecveEventToAnalyzer(e *executionEvent) error {
	if analyzerConn == nil {
		return nil
	}

	event := analyzerExecveEvent{
		Timestamp: getTimestamp(),
		EventType: "flow",
		Sensor:    "ebpf-anomaly-detector",
		Host:      "localhost",
		Proto:     "TCP",

		Filename: cString(e.Filename[:]),
		Argv:     cString(e.Argv[:]),

		Process: analyzerProcess{
			Pid:  e.Header.Pid,
			Comm: cString(e.Header.Comm[:]),
		},

		Flow: analyzerFlow{
			State: "established",
		},
	}

	return sendAnalyzerEvent(event)
}

func sendOpenatEventToAnalyzer(e *openingEvent) error {
	if analyzerConn == nil {
		return nil
	}

	event := analyzerOpenatEvent{
		Timestamp: getTimestamp(),
		EventType: "flow",
		Sensor:    "ebpf-anomaly-detector",
		Host:      "localhost",
		Proto:     "TCP",

		Pathname:   cString(e.Pathname[:]),
		Dirfd:      e.Dirfd,
		Flags:      e.Flags,
		Mode:       e.Mode,
		Result:     int64(e.Header.Res),
		DurationNs: e.DurationNs,

		Process: analyzerProcess{
			Pid:  e.Header.Pid,
			Comm: cString(e.Header.Comm[:]),
		},

		Flow: analyzerFlow{
			State: "established",
		},
	}

	return sendAnalyzerEvent(event)
}

func sendAnalyzerEvent(event any) error {
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
