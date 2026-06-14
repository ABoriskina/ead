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
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const taskCommLen = 16

type tcpConnectionEvent struct {
	Pid   uint32
	Comm  [taskCommLen]byte
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
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

	spec, err := ebpf.LoadCollectionSpec("connections.bpf.o")
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

	var key uint32 = 0

	if err := configMap.Put(key, port); err != nil {
		log.Fatalf("failed to update tcp_connection_config: %v", err)
	}

	prog, ok := collection.Programs["trace_tcp_state"]
	if !ok {
		log.Fatal("failed to find BPF program trace_tcp_state")
	}

	tp, err := link.Tracepoint(
		"sock",
		"inet_sock_set_state",
		prog,
		nil,
	)
	if err != nil {
		log.Fatalf("failed to attach BPF program: %v", err)
	}
	defer tp.Close()

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
		"pid=%d comm=%s %s:%d -> %s:%d\n",
		event.Pid,
		cString(event.Comm[:]),
		srcIP,
		event.Sport,
		dstIP,
		event.Dport,
	)

	return nil
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
