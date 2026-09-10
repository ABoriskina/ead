import json
import os
from pathlib import Path
import queue
import socket
import threading
import time
from typing import Any
from urllib import request

from prometheus_client import Counter, Gauge, start_http_server

from .correlation import get_context_weight, get_adjusted_weight
from .correlation_config import (
    CONFIG_PATH,
    load_correlation_config,
    prepare_correlation_config,
)
from .graph import EventGraph
from .visualization import visualize_graph
from .patterns import EVENT_FILE_PROBE


AGENT_HOST = "0.0.0.0"
AGENT_PORT = 9000

METRICS_HOST = "0.0.0.0"
METRICS_PORT = 9200

FLUSH_GRAPH = object()


event_queue = queue.Queue(maxsize=10_000)
alert_queue = queue.Queue(maxsize=1_000)
event_graph = EventGraph()

correlation_config_path = prepare_correlation_config()
correlation_config = load_correlation_config(correlation_config_path)
correlation_config_mtime = correlation_config_path.stat().st_mtime_ns

graph_output_path = Path(__file__).resolve().parent / "event-graph.html"
WEB_ALERT_URL = os.getenv("EAD_WEB_ALERT_URL", "http://127.0.0.1:8080/api/alerts")

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

alerts_total = Counter(
    "ead_alerts_total",
    "Total number of generated alerts",
)

agents_connected = Gauge(
    "ead_agents_connected",
    "Number of agents currently connected to the analyzer",
)


def reload_correlation_config_if_changed():
    global correlation_config, correlation_config_mtime

    config_path = CONFIG_PATH
    current_mtime = config_path.stat().st_mtime_ns
    if current_mtime == correlation_config_mtime:
        return

    try:
        next_config = load_correlation_config(config_path)
    except Exception as error:
        print(f"Cannot reload correlation config: {error}")
        return

    correlation_config = next_config
    correlation_config_mtime = current_mtime
    print(f"Reloaded correlation config: {config_path}")


def publish_alert(event: dict[str, Any], score: float):
    try:
        alert_queue.put_nowait({"score": score, "event": event})
    except queue.Full:
        print("Web alert queue is full, alert dropped")


def alert_publisher():
    while True:
        alert = alert_queue.get()
        try:
            payload = json.dumps(alert).encode("utf-8")
            http_request = request.Request(
                WEB_ALERT_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with request.urlopen(http_request, timeout=1):
                pass
        except Exception as error:
            print(f"Cannot publish alert to web interface: {error}")
        finally:
            alert_queue.task_done()


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


def logical_process_node_id(event: dict[str, Any]) -> str:
    process = event.get("process", {})
    return f"process:{event.get('host', 'unknown')}:{process.get('pid', 'unknown')}"


def process_node_id(event: dict[str, Any]) -> str:
    return event_graph.current_process_node(logical_process_node_id(event))


def executable_name(pathname: Any) -> str:
    name = Path(str(pathname)).name
    return name or "<unknown>"


def classify_operation(
    event_type: str,
    event_data: dict[str, Any],
) -> tuple[str, str]:
    raw_operation = str(event_data.get("operation", "UNKNOWN"))

    if event_type == "EVENT_CLONE":
        return "process", "CREATE"
    if event_type == "EVENT_EXECVE":
        return "file", "EXECUTE"
    if event_type == "EVENT_OPENAT":
        if event_data.get("is_create_requested") and event_data.get("success"):
            return "file", "CREATE"
        return "file", raw_operation
    if event_type in {"EVENT_RENAME", "EVENT_FCHMOD", "EVENT_UNLINK"}:
        return "file", raw_operation
    if event_type in EVENT_FILE_PROBE:
        return "file", raw_operation
    if event_type == "EVENT_CONNECT":
        return "network", raw_operation

    return "unknown", raw_operation


def add_event_to_graph(event: dict[str, Any]) -> float:
    event_type = event.get("event_type", "unknown")
    event_data = event.get("event", {})
    process = event.get("process", {})
    raw_operation = str(event_data.get("operation", "UNKNOWN"))
    operation_entity_type, operation = classify_operation(
        event_type,
        event_data,
    )
    timestamp_ns = int(event_data.get("timestamp_ns", 0))

    logical_process_id = logical_process_node_id(event)
    event_graph.register_process_node(logical_process_id)
    process_id = event_graph.current_process_node(logical_process_id)
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
    edge_attributes["source_operation"] = raw_operation
    edge_attributes["operation_entity_type"] = operation_entity_type
    edge_attributes["event_type"] = event_type

    if operation_entity_type != "unknown":
        base_weight = correlation_config.base_weight_for(
            operation_entity_type,
            operation
        )
        edge_attributes["base_weight"] = (base_weight)

        normalized_base_weight = correlation_config.normalized_base_weight_for(
            operation_entity_type,
            operation,
        )
        edge_attributes["normalized_base_weight"] = (normalized_base_weight)
    else:
        edge_attributes["base_weight"] = 0.0
        edge_attributes["normalized_base_weight"] = 0.0
        normalized_base_weight = 0.0

    if event_type == "EVENT_EXECVE" and event_data.get("success", False):
        pathname = event_data.get("pathname", "<unknown>")
        image_id = f"{logical_process_id}:exec:{timestamp_ns}"
        event_graph.add_process(
            image_id,
            pid=process.get("pid"),
            tid=process.get("tid"),
            uid=process.get("uid"),
            comm=executable_name(pathname),
            executable=pathname,
        )
        event_graph.add_event(
            process_id,
            image_id,
            operation,
            timestamp_ns,
            **edge_attributes,
        )
        event_graph.set_current_process_node(logical_process_id, image_id)

    elif event_type == "EVENT_CONNECT":
        address = event_data.get("dst_ip", "unknown")
        port = event_data.get("dst_port", "unknown")
        target_id = f"network:{address}:{port}"
        event_graph.add_network(target_id, address=address, port=port)
        event_graph.add_event(
            process_id, target_id, operation, timestamp_ns, **edge_attributes
        )

    elif event_type in {"EVENT_EXECVE", "EVENT_OPENAT", "EVENT_FCHMOD", "EVENT_UNLINK"} | EVENT_FILE_PROBE:
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
            source_operation="RENAME_REQUEST",
            operation_entity_type="synthetic",
            base_weight=0.0,
            normalized_base_weight=0.0,
            synthetic=True,
        )
        event_graph.add_event(
            old_id, new_id, operation, timestamp_ns, **edge_attributes
        )

    elif event_type == "EVENT_CLONE":
        child_pid = event_data.get("created_task_id")
        child_id = f"process:{event.get('host', 'unknown')}:{child_pid}"
        if child_id not in event_graph.graph:
            event_graph.add_process(
                child_id,
                pid=child_pid,
                comm="<unknown>",
            )
        event_graph.register_process_node(child_id)
        event_graph.add_event(
            process_id, child_id, operation, timestamp_ns, **edge_attributes
        )

    else:
        target_id = f"event:{event_type}:{timestamp_ns}"
        event_graph.graph.add_node(target_id, entity_type="event", event_type=event_type)
        event_graph.add_event(
            process_id, target_id, operation, timestamp_ns, **edge_attributes
        )
    return normalized_base_weight


def render_graph():
    started = time.monotonic()

    visualize_graph(
        event_graph.graph,
        str(graph_output_path),
    )

    duration = time.monotonic() - started
    print(
        f"Graph rendered: "
        f"{event_graph.graph.number_of_nodes()} nodes, "
        f"{event_graph.graph.number_of_edges()} edges, "
        f"duration={duration:.3f}s; "
        f"file://{graph_output_path}"
    )


def handle_event(event: dict[str, Any]) -> float:
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
    reload_correlation_config_if_changed()
    update_metrics(event)

    event_data = event.get("event", {})
    timestamp_ns = int(event_data.get("timestamp_ns", 0))

    normalized_base_weight = add_event_to_graph(event)

    """
    if is_anchor_event(event):
        context_weight, pattern_similarity = get_context_weight(event, event_graph.graph, correlation_config)
        print(f"Context weight: {context_weight:.6f}, pattern: {pattern_similarity}, timestamp: {timestamp_ns}")

        adjusted_weight = get_adjusted_weight(context_weight, normalized_base_weight)
        print(f"Adjusted weight: {adjusted_weight:.6f}")

        if pattern_similarity > 0:
            alerts_total.inc()
            publish_alert(event, adjusted_weight)

        return adjusted_weight
    """


def correlation_worker():
    dirty = False

    while True:
        item = event_queue.get()

        try:
            if item is None:
                if dirty:
                    render_graph()
                return

            if item is FLUSH_GRAPH:
                if dirty:
                    render_graph()
                    dirty = False
                continue

            handle_event(item)
            dirty = True

        except Exception as error:
            print(f"Correlation error: {error}")
        finally:
            event_queue.task_done()


def handle_agent(conn: socket.socket, addr: tuple[str, int]):
    print(f"Agent connected: {addr}")
    agents_connected.inc()

    try:
        with conn:
            file = conn.makefile("r", encoding="utf-8")

            for line in file:
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError as error:
                    print(f"Invalid JSON: {error}")
                    continue

                try:
                    event_queue.put(event, timeout=1)
                except queue.Full:
                    print("Event queue is full, event dropped")
    finally:
        event_queue.put(FLUSH_GRAPH)
        agents_connected.dec()

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

    publisher = threading.Thread(
        target=alert_publisher, daemon=True
    )
    publisher.start()

    start_http_server(METRICS_PORT, addr=METRICS_HOST)
    run_agent_server()


if __name__ == "__main__":
    main()
