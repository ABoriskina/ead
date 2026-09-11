import networkx as nx
import time
from pathlib import Path
from typing import Any


from .visualization import visualize_graph
from .patterns import EVENT_GROUPS
from .correlation_config import CorrelationConfig


def get_subgraph(
    graph: nx.MultiDiGraph,
    anchor_node_id: str,
    anchor_timestamp_ns: int,
    max_depth: int,
    time_window_seconds: float,
) -> nx.MultiDiGraph:
    window_ns = int(time_window_seconds * 1_000_000_000)
    window_start_ns = anchor_timestamp_ns - window_ns

    visited_edges: set[tuple[str, str, int]] = set()
    frontier = [(anchor_node_id, 0, anchor_timestamp_ns)]

    while frontier:
        node, depth, latest_timestamp_ns = frontier.pop()

        if depth >= max_depth:
            continue

        for source, target, key, attributes in graph.in_edges(
            node,
            keys=True,
            data=True,
        ):
            edge_id = (source, target, key)
            if edge_id in visited_edges:
                continue

            edge_timestamp_ns = int(attributes.get("timestamp_ns", 0))
            if edge_timestamp_ns < window_start_ns:
                continue

            if edge_timestamp_ns > latest_timestamp_ns:
                continue

            visited_edges.add(edge_id)
            frontier.append((source, depth + 1, edge_timestamp_ns))

    if not visited_edges:
        subgraph = nx.MultiDiGraph()
        if anchor_node_id in graph:
            subgraph.add_node(
                anchor_node_id,
                **graph.nodes[anchor_node_id],
            )
        return subgraph

    return graph.edge_subgraph(visited_edges).copy()


class EventGraph:
    def __init__(self):
        self.graph = nx.MultiDiGraph()
        self._current_process_nodes: dict[str, str] = {}

    def current_process_node(self, process_id: str) -> str:
        return self._current_process_nodes.get(process_id, process_id)

    def register_process_node(self, process_id: str):
        self._current_process_nodes.setdefault(process_id, process_id)

    def set_current_process_node(self, process_id: str, node_id: str):
        self._current_process_nodes[process_id] = node_id

    def add_process(self, process_id: str, **attributes):
        self.graph.add_node(
            process_id,
            entity_type="process",
            **attributes,
        )

    def add_file(self, file_id: str, **attributes):
        self.graph.add_node(
            file_id,
            entity_type="file",
            **attributes,
        )

    def add_network(self, network_id: str, **attributes):
        self.graph.add_node(
            network_id,
            entity_type="network",
            **attributes,
        )

    def add_event(
        self,
        subject_id: str,
        object_id: str,
        operation: str,
        timestamp_ns: int,
        **attributes,
    ):
        self.graph.add_edge(
            subject_id,
            object_id,
            operation=operation,
            timestamp_ns=timestamp_ns,
            **attributes,
        )


def logical_process_node_id(event: dict[str, Any]) -> str:
    process = event.get("process", {})
    return f"process:{event.get('host', 'unknown')}:{process.get('pid', 'unknown')}"


def process_node_id(event: dict[str, Any], event_graph: EventGraph,) -> str:
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
    if event_type in EVENT_GROUPS["FILE_PROBE"]:
        return "file", raw_operation
    if event_type == "EVENT_CONNECT":
        return "network", raw_operation

    return "unknown", raw_operation




def render_graph(event_graph: EventGraph):
    graph_output_path = Path(__file__).resolve().parent / "event-graph.html"
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


def add_event_to_graph(event: dict[str, Any], correlation_config: CorrelationConfig, 
                       event_graph: EventGraph, event_id: str) -> float:
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
    edge_attributes["event_id"] = event_id

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

    elif event_type in {"EVENT_EXECVE", "EVENT_OPENAT", "EVENT_FCHMOD", "EVENT_UNLINK"} | EVENT_GROUPS["FILE_PROBE"]:
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
    render_graph(event_graph)
    return normalized_base_weight
