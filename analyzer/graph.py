import networkx as nx


def collect_ancestors(graph, start_node, max_depth):
    visited = {start_node}
    frontier = [(start_node, 0)]

    while frontier:
        node, depth = frontier.pop()

        if depth >= max_depth:
            continue

        for parent in graph.predecessors(node):
            if parent in visited:
                continue

            visited.add(parent)
            frontier.append((parent, depth + 1))

    return visited

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
