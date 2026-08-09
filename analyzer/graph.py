import networkx as nx


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
