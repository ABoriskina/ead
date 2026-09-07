from typing import Any
import networkx as nx
from .correlation_config import CorrelationConfig
from .graph import get_subgraph
from .patterns import check_in_patterns, pattern_variant_lengths


NANOSECONDS_IN_SECOND = 1_000_000_000


def calculate_time_factor(
    anchor_timestamp_ns: int, 
    event_timestamp_ns: int, 
    half_life_seconds: float
    ) -> float:
    if event_timestamp_ns > anchor_timestamp_ns:
        return 0.0

    delta_time_ns = anchor_timestamp_ns - event_timestamp_ns
    delta_time_seconds = delta_time_ns / NANOSECONDS_IN_SECOND
    exponent = delta_time_seconds / half_life_seconds
    return 0.5 ** exponent


def calculate_distance_factor(distance: int) -> float:
    return 1 / (1 + distance)


def calculate_causal_relationship(
    anchor_timestamp_ns: int,
    event_timestamp_ns: int,
    distance: int,
    half_life_seconds: float,
) -> float:
    time_factor = calculate_time_factor(
        anchor_timestamp_ns,
        event_timestamp_ns,
        half_life_seconds,
    )
    distance_factor = calculate_distance_factor(distance)
    return time_factor * distance_factor


def get_context_weight(
    event: dict[str, Any],
    graph: nx.MultiDiGraph,
    config: CorrelationConfig,
) -> tuple[float, int]:
    event_data = event.get("event", {})
    anchor_timestamp_ns = int(event_data.get("timestamp_ns", 0))
    anchor_operation = event_data.get("operation", "UNKNOWN")

    anchor_edge = _find_anchor_edge(
        graph,
        anchor_timestamp_ns,
        anchor_operation,
    )
    if anchor_edge is None:
        return 0.0, 0

    anchor_source, _, _ = anchor_edge
    _, anchor_target, _ = anchor_edge
    local_subgraph = get_subgraph(
        graph=graph,
        anchor_node_id=anchor_target,
        anchor_timestamp_ns=anchor_timestamp_ns,
        max_depth=config.traversal_depth + 1,
        time_window_seconds=config.time_window,
    )

    contributions: list[float] = []
    pattern_similarity = get_pattern_similarity(
        graph,
        anchor_timestamp_ns,
        config.time_window,
        anchor_edge,
        {
            node_id
            for node_id, attributes in local_subgraph.nodes(data=True)
            if attributes.get("entity_type") == "process"
        },
    )

    graph_edges = sorted(
        local_subgraph.edges(keys=True, data=True),
        key=lambda edge: int(edge[3].get("timestamp_ns", 0)),
    )
    for source, target, key, attributes in graph_edges:
        if (source, target, key) == anchor_edge:
            continue
        if attributes.get("synthetic", False):
            continue

        try:
            distance = nx.shortest_path_length(
                local_subgraph,
                source=target,
                target=anchor_source,
            )
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue

        contributions.append(
            calculate_causal_relationship(
                anchor_timestamp_ns=anchor_timestamp_ns,
                event_timestamp_ns=int(attributes.get("timestamp_ns", 0)),
                distance=distance + 1,
                half_life_seconds=config.time_window,
            )
        )

    if not contributions:
        return 0.0, pattern_similarity

    return sum(contributions) / len(contributions), pattern_similarity


def get_pattern_similarity(
    graph: nx.MultiDiGraph,
    anchor_timestamp_ns: int,
    time_window_seconds: float,
    anchor_edge: tuple[str, str, int],
    lineage_process_nodes: set[str],
    pattern_name: str = "SH-1",
) -> int:
    window_start_ns = anchor_timestamp_ns - int(
        time_window_seconds * NANOSECONDS_IN_SECOND
    )
    candidate_edges = sorted(
        (
            edge
            for edge in graph.edges(keys=True, data=True)
            if window_start_ns
            <= int(edge[3].get("timestamp_ns", 0))
            <= anchor_timestamp_ns
            and edge[0] in lineage_process_nodes
        ),
        key=lambda edge: int(edge[3].get("timestamp_ns", 0)),
    )

    variant_lengths = pattern_variant_lengths(pattern_name)
    variant_steps = [0] * len(variant_lengths)
    for source, target, key, attributes in candidate_edges:
        for variant_index, variant_length in enumerate(variant_lengths):
            step = variant_steps[variant_index]
            if step >= variant_length:
                continue
            if not check_in_patterns(
                graph.nodes[source],
                graph.nodes[target],
                key,
                attributes,
                step,
                pattern_name,
                variant_index,
            ):
                continue

            variant_steps[variant_index] += 1
            if (
                variant_steps[variant_index] == variant_length
                and (source, target, key) == anchor_edge
            ):
                return variant_length

    return 0


def get_adjusted_weight(context_weight, normalized_base_weight) -> float:
    if not 0.0 <= context_weight <= 1.0:
        raise ValueError("context_weight must be between 0 and 1")
    if not 0.0 <= normalized_base_weight <= 1.0:
        raise ValueError("normalized_base_weight must be between 0 and 1")

    return normalized_base_weight * (1 + 0.5 * context_weight)


def _find_anchor_edge(
    graph: nx.MultiDiGraph,
    timestamp_ns: int,
    operation: str,
) -> tuple[str, str, int] | None:
    for source, target, key, attributes in graph.edges(
        keys=True,
        data=True,
    ):
        if int(attributes.get("timestamp_ns", 0)) != timestamp_ns:
            continue
        if (
            attributes.get("operation") != operation
            and attributes.get("source_operation") != operation
        ):
            continue

        return source, target, key

    return None
