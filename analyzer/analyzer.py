import json
import socket
import threading
import time
from typing import Any

from prometheus_client import Counter, Gauge, start_http_server

AGENT_HOST = "0.0.0.0"
AGENT_PORT = 9000

METRICS_HOST = "0.0.0.0"
METRICS_PORT = 9200


events_total = Counter(
    "ead_events_total",
    "Total number of received events",
    ["event_type"],
)

tcp_connections_total = Counter(
    "ead_tcp_connections_total",
    "Total number of observed TCP connection events",
)

tcp_connections_by_process = Counter(
    "ead_tcp_connections_by_process_total",
    "TCP connection events grouped by process name",
    ["comm"],
)

last_event_timestamp = Gauge(
    "ebpf_ids_last_event_timestamp_seconds",
    "Timestamp of the last received event",
)


def update_metrics(event: dict[str, Any]):
    event_type = event.get("event_type", "unknown")

    events_total.labels(event_type=event_type).inc()
    last_event_timestamp.set(time.time())

    if event_type == "flow":
        process = event.get("process", {})
        comm = process.get("comm", "unknown")
        dest_port = str(event.get("dest_port", "unknown"))

        tcp_connections_total.inc()
        tcp_connections_by_process.labels(comm=comm).inc()


def handle_event(event: dict[str, Any]):
    update_metrics(event)

    if event.get("event_type") == "flow":
        process = event.get("process", {})
        print(
            f"{event.get('src_ip')}:{event.get('src_port')} -> "
            f"{event.get('dest_ip')}:{event.get('dest_port')} "
            f"pid={process.get('pid')} comm={process.get('comm')}"
        )


def handle_agent(conn: socket.socket, addr: tuple[str, int]):
    print(f"Agent connected: {addr}")

    with conn:
        file = conn.makefile("r", encoding="utf-8")

        for line in file:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"Invalid JSON: {line}")
                continue

            handle_event(event)

    print(f"Agent disconnected: {addr}")


def run_agent_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((AGENT_HOST, AGENT_PORT))
        server.listen()

        print(f"Analyzer waits for agent on port {AGENT_PORT}")

        while True:
            conn, addr = server.accept()
            thread = threading.Thread(
                target=handle_agent, args=(conn, addr), daemon=True
            )
            thread.start()


def main():
    start_http_server(METRICS_PORT, addr=METRICS_HOST)
    run_agent_server()


if __name__ == "__main__":
    main()
