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
from .graph import render_graph
from .buffer import EventBuffer
from .constants import WINDOW_SIZE
from .patterns import anchor_reasons
from .candidates import find_related_candidates


AGENT_HOST = "0.0.0.0"
AGENT_PORT = 9000

METRICS_HOST = "0.0.0.0"
METRICS_PORT = 9200

FLUSH_GRAPH = object()


event_queue = queue.Queue(maxsize=10_000)
alert_queue = queue.Queue(maxsize=1_000)
event_buffer = EventBuffer(window_seconds=WINDOW_SIZE)

active_candidates = {}
process_candidates = {}

correlation_config_path = prepare_correlation_config()
correlation_config = load_correlation_config(correlation_config_path)
correlation_config_mtime = correlation_config_path.stat().st_mtime_ns

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


def handle_event(event: dict[str, Any]) -> None:
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

    buffered_event = event_buffer.append(event)
    reasons = anchor_reasons(event)
    if reasons:
        print(
            f"Anchor event: {buffered_event.event_id}; "
            f"reasons: {', '.join(sorted(reasons))}"
        )

    search = find_related_candidates(
        host=event["host"],
        pid=event["process"]["pid"],
        timestamp_ns=int(event["event"]["timestamp_ns"]),
        event_buffer=event_buffer,
        process_candidates=process_candidates,
        active_candidates=active_candidates,
    )

    if search.candidate_ids:
        ...
    elif reasons:
        ...


def event_processor():
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
        target=event_processor, daemon=True
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
