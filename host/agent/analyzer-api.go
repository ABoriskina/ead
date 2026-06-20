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

	Process analyzerProcess `json:"process"`
	Flow    analyzerFlow    `json:"flow"`
}

type analyzerProcess struct {
	Pid  uint32 `json:"pid"`
	Comm string `json:"comm"`
}

type analyzerFlow struct {
	State string `json:"state"`
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