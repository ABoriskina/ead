import json
from pathlib import Path
import queue
import socket
import threading
import time
from typing import Any

from prometheus_client import Counter, Gauge, start_http_server

from .graph import EventGraph
from .visualization import visualize_graph


AGENT_HOST = "0.0.0.0"
AGENT_PORT = 9000

METRICS_HOST = "0.0.0.0"
METRICS_PORT = 9200


event_queue = queue.Queue(maxsize=10_000)
event_graph = EventGraph()
graph_output_path = Path(__file__).resolve().parent / "event-graph.html"

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

    if event_type == "EVENT_CONNECT":
        process = event.get("process", {})
        comm = process.get("comm", "unknown")

        tcp_connections_total.inc()
        tcp_connections_by_process.labels(comm=comm).inc()


def is_anchor_event(_event: dict[str, Any]) -> bool:
    return True # plug


def process_node_id(event: dict[str, Any]) -> str:
    process = event.get("process", {})
    return f"process:{event.get('host', 'unknown')}:{process.get('pid', 'unknown')}"


def add_event_to_graph(event: dict[str, Any]) -> None:
    event_type = event.get("event_type", "unknown")
    event_data = event.get("event", {})
    process = event.get("process", {})
    operation = event_data.get("operation", "UNKNOWN")
    timestamp_ns = int(event_data.get("timestamp_ns", 0))

    process_id = process_node_id(event)
    event_graph.add_process(
        process_id,
        pid=process.get("pid"),
        tid=process.get("tid"),
        uid=process.get("uid"),
        comm=process.get("comm", "unknown"),
    )

    edge_attributes = {
        name: value
        for name, value in event_data.items()
        if name not in {"operation", "timestamp_ns"}
    }

    if event_type == "EVENT_CONNECT":
        address = event_data.get("dst_ip", "unknown")
        port = event_data.get("dst_port", "unknown")
        target_id = f"network:{address}:{port}"
        event_graph.add_network(target_id, address=address, port=port)
        event_graph.add_event(
            process_id, target_id, operation, timestamp_ns, **edge_attributes
        )

    elif event_type in {"EVENT_EXECVE", "EVENT_OPENAT", "EVENT_FCHMOD", "EVENT_UNLINK"}:
        pathname = event_data.get("pathname", "<unknown>")
        target_id = f"file:{pathname}"
        event_graph.add_file(target_id, pathname=pathname)
        event_graph.add_event(
            process_id, target_id, operation, timestamp_ns, **edge_attributes
        )

    elif event_type == "EVENT_RENAME":
        oldname = event_data.get("oldname", "<unknown-old>")
        newname = event_data.get("newname", "<unknown-new>")
        old_id = f"file:{oldname}"
        new_id = f"file:{newname}"
        event_graph.add_file(old_id, pathname=oldname)
        event_graph.add_file(new_id, pathname=newname)
        event_graph.add_event(
            process_id,
            old_id,
            "RENAME_REQUEST",
            timestamp_ns,
            **edge_attributes,
        )
        event_graph.add_event(
            old_id, new_id, operation, timestamp_ns, **edge_attributes
        )

    elif event_type == "EVENT_CLONE":
        child_pid = event_data.get("created_task_id")
        child_id = f"process:{event.get('host', 'unknown')}:{child_pid}"
        event_graph.add_process(child_id, pid=child_pid, comm="<unknown>")
        event_graph.add_event(
            process_id, child_id, operation, timestamp_ns, **edge_attributes
        )

    else:
        target_id = f"event:{event_type}:{timestamp_ns}"
        event_graph.graph.add_node(target_id, entity_type="event", event_type=event_type)
        event_graph.add_event(
            process_id, target_id, operation, timestamp_ns, **edge_attributes
        )


def handle_event(event: dict[str, Any]):
    """
    {
        "timestamp":"2026-08-29T09:16:04.368074Z",
        "event_type":"EVENT_UNLINK",
        "sensor":"ebpf-anomaly-detector",
        "host":"localhost",
        "process":
            {"pid":170870,"tid":170877,"uid":1000,"comm":"Compositor"},
        "event":
            {"fd":-100,"flags":0,"operation":"DELETE","pathname":"/dev/shm/.org",
            "result":0,"success":true,"syscall_type":11,"timestamp_ns":"1787994964366003142","type":12}
    }
    """
    update_metrics(event)

    if is_anchor_event(event):
        add_event_to_graph(event)
        visualize_graph(event_graph.graph, str(graph_output_path))
        print(
            f"Graph updated: {event_graph.graph.number_of_nodes()} nodes, "
            f"{event_graph.graph.number_of_edges()} edges; file://{graph_output_path}"
        )


def correlation_worker():
    while True:
        event = event_queue.get()

        try:
            if event is None:
                return

            handle_event(event)
        except Exception as error:
            print(f"Correlation error: {error}")
        finally:
            event_queue.task_done()


def handle_agent(conn: socket.socket, addr: tuple[str, int]):
    print(f"Agent connected: {addr}")

    with conn:
        file = conn.makefile("r", encoding="utf-8")
        for line in file:
            line = line.strip()
            if not line:
                continue

            print(f"Received raw: {line}")

            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                print(f"Invalid JSON: {error}")
                print(f"Raw data: {line}")
                continue

            try:
                event_queue.put(event, timeout=1)
            except queue.Full:
                print("Event queue is full, event dropped")

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
    worker = threading.Thread(
        target=correlation_worker, daemon=True
    )
    worker.start()

    start_http_server(METRICS_PORT, addr=METRICS_HOST)
    run_agent_server()


if __name__ == "__main__":
    main()
