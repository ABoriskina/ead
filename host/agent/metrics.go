package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

const (
	agentMetricsPath     = "agent-metrics.jsonl"
	agentMetricsInterval = time.Minute
	maxMetricsSnapshots  = 60
)

type agentMetricsSnapshot struct {
	TimestampMs          int64             `json:"timestamp_ms"`
	ReceivedFromBPF      uint64            `json:"received_from_bpf"`
	SentToAnalyzer       uint64            `json:"sent_to_analyzer"`
	NotForwarded         uint64            `json:"not_forwarded"`
	FilteredByPath       uint64            `json:"filtered_by_path"`
	FailedOpenat         uint64            `json:"failed_openat"`
	DuplicateOpenatLSM   uint64            `json:"duplicate_openat_lsm"`
	NoAnalyzerConnection uint64            `json:"no_analyzer_connection"`
	HandlingErrors       uint64            `json:"handling_errors"`
	SendErrors           uint64            `json:"send_errors"`
	EventCounts          map[string]uint64 `json:"event_counts"`
	FilteredEventCounts  map[string]uint64 `json:"filtered_event_counts"`
}

type metricsRecorder struct {
	stop chan struct{}
	done chan struct{}
}

func snapshotAgentMetrics() agentMetricsSnapshot {
	received := receivedEvents.Load()
	sent := analyzerEventsSent.Load()
	filteredByPath := uint64(0)
	eventCounts := make(map[string]uint64)
	filteredEventCounts := make(map[string]uint64)

	for kind := eventType(0); kind <= eventFileOpen; kind++ {
		if count := receivedEventsByType[kind].Load(); count > 0 {
			eventCounts[eventTypeName(kind)] = count
		}
		if count := filteredEventsByType[kind].Load(); count > 0 {
			filteredEventCounts[eventTypeName(kind)] = count
			filteredByPath += count
		}
	}
	if unknown := receivedEventsWithUnknownType.Load(); unknown > 0 {
		eventCounts["UNKNOWN"] = unknown
	}

	notForwarded := uint64(0)
	if received >= sent {
		notForwarded = received - sent
	}

	return agentMetricsSnapshot{
		TimestampMs:          time.Now().UnixMilli(),
		ReceivedFromBPF:      received,
		SentToAnalyzer:       sent,
		NotForwarded:         notForwarded,
		FilteredByPath:       filteredByPath,
		FailedOpenat:         failedOpenatEvents.Load(),
		DuplicateOpenatLSM:   duplicateOpenEvents.Load(),
		NoAnalyzerConnection: analyzerEventsWithoutConnection.Load(),
		HandlingErrors:       eventHandlingErrors.Load(),
		SendErrors:           analyzerSendErrors.Load(),
		EventCounts:          eventCounts,
		FilteredEventCounts:  filteredEventCounts,
	}
}

func appendAgentMetrics() error {
	data, err := json.Marshal(snapshotAgentMetrics())
	if err != nil {
		return fmt.Errorf("marshal agent metrics: %w", err)
	}

	existing, err := os.ReadFile(agentMetricsPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read agent metrics file: %w", err)
	}
	lines := bytes.Split(bytes.TrimSpace(existing), []byte{'\n'})
	if len(existing) == 0 {
		lines = nil
	}
	lines = append(lines, data)
	if len(lines) > maxMetricsSnapshots {
		lines = lines[len(lines)-maxMetricsSnapshots:]
	}
	output := append(bytes.Join(lines, []byte{'\n'}), '\n')

	if err := os.WriteFile(agentMetricsPath, output, 0644); err != nil {
		return fmt.Errorf("write agent metrics: %w", err)
	}
	return nil
}

func startMetricsRecorder() *metricsRecorder {
	recorder := &metricsRecorder{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}

	go func() {
		defer close(recorder.done)
		ticker := time.NewTicker(agentMetricsInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := appendAgentMetrics(); err != nil {
					log.Printf("failed to save periodic agent metrics: %v", err)
				}
			case <-recorder.stop:
				return
			}
		}
	}()

	return recorder
}

func (recorder *metricsRecorder) stopAndWriteFinal() {
	close(recorder.stop)
	<-recorder.done
	if err := appendAgentMetrics(); err != nil {
		log.Printf("failed to save final agent metrics: %v", err)
		return
	}
	log.Printf("Agent metrics saved to %s", agentMetricsPath)
}
