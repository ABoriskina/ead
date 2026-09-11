from uuid import uuid4

from .candidates import Candidate
from .buffer import BufferedEvent
from .patterns import PATTERNS, entity_groups

# находим ребра нового события
def edges_for_event(
    candidate: Candidate,
    event_id: str,
) -> list[tuple[str, str, int, dict]]:
    return [
        (source, target, key, attributes)
        for source, target, key, attributes in candidate.graph.graph.edges(
            keys=True,
            data=True,
        )
        if attributes.get("event_id") == event_id
    ]


# подходит ли вершина под source или target
def node_matches(
    attributes: dict,
    condition: dict,
) -> bool:
    expected_type = condition.get("entity_type")

    if (
        expected_type is not None
        and attributes.get("entity_type") != expected_type
    ):
        return False

    expected_groups = set(condition.get("entity_groups", []))

    if expected_groups:
        actual_groups = entity_groups(attributes)

        if not (actual_groups & expected_groups):
            return False

    return True


# проверка ребер на совпадение с шаблоном
def edge_matches_stage(
    candidate: Candidate,
    source_id: str,
    target_id: str,
    edge_attributes: dict,
    stage: dict,
    bindings: dict[str, str],
    last_timestamp_ns: int | None,
) -> bool:
    graph = candidate.graph.graph
    source_condition = stage["source"]
    target_condition = stage["target"]
    edge_condition = stage["edge"]

    if edge_attributes.get("event_type") != edge_condition["event_type"]:
        return False
    if (
        edge_condition.get("require_success")
        and edge_attributes.get("success") is not True
    ):
        return False

    allowed_operations = set(edge_condition.get("operations", []))
    if (
        allowed_operations
        and edge_attributes.get("operation") not in allowed_operations
    ):
        return False

    source_role = source_condition.get("role")
    target_role = target_condition.get("role")

    # если роль уже известна то новое ребро должно использовать
    # именно ранее связанный узел
    if (
        source_role in bindings
        and bindings[source_role] != source_id
    ):
        return False

    if (
        target_role in bindings
        and bindings[target_role] != target_id
    ):
        return False

    if not node_matches(graph.nodes[source_id], source_condition):
        return False

    if not node_matches(graph.nodes[target_id], target_condition):
        return False

    within_seconds = stage.get("within_seconds")
    timestamp_ns = int(edge_attributes["timestamp_ns"])

    if (
        within_seconds is not None
        and last_timestamp_ns is not None
        and timestamp_ns - last_timestamp_ns
        > within_seconds * 1_000_000_000
    ):
        return False

    return True


def bind_stage_roles(
    bindings: dict[str, str],
    stage: dict,
    source_id: str,
    target_id: str,
) -> dict[str, str]:
    next_bindings = dict(bindings)

    source_role = stage["source"].get("role")
    target_role = stage["target"].get("role")

    if source_role is not None:
        next_bindings.setdefault(source_role, source_id)

    if target_role is not None:
        next_bindings.setdefault(target_role, target_id)

    return next_bindings


    """
    "stages": [
    {
        "id": "manager_reads_manifest",
        "weight": BASE_WEIGHTS["manager_reads_manifest"], для прохода
        "required": True,                                 для прохода
        "can_be_duplicated" : False,
        "source": {
            "role": "package_manager",
            "entity_type": "process",
            "entity_groups": ["package_manager"],
        },
        "edge": {
            "event_type": "EVENT_OPENAT",
            "operations": ["OPEN_READ"],
        },
        "target": {
            "role": "package_manifest",                   для прохода
            "entity_type": "file",                        для прохода
            "entity_groups": ["package_manifest"],        для прохода
        },
    },
    for event_id, entry in candidate.events.items():
    """
def update_candidate_matches(
    buffered_event: BufferedEvent,
    candidate: Candidate,
) -> None:
    print(f"\n\n CANDIDATES WEEEEEEEHOOOOOO\n{candidate.match_ids_by_event}\n")
    event_id = buffered_event.event_id
    graph_edges = edges_for_event(candidate, event_id)

    if not graph_edges:
        return

    # продвигаем уже начатые, но ещё не завершённые совпадения
    for match_id, match in list(candidate.active_matches.items()):
        pattern = PATTERNS[match["pattern_id"]]

        alternative = next(
            alternative
            for alternative in pattern["alternatives"]
            if alternative["id"] == match["alternative_id"]
        )

        stage_index = match["next_stage_index"]

        # match уже завершён, его не продолжаем
        if stage_index >= len(alternative["stages"]):
            continue

        next_stage = alternative["stages"][stage_index]

        for source_id, target_id, _, edge_attributes in graph_edges:
            if not edge_matches_stage(
                candidate,
                source_id,
                target_id,
                edge_attributes,
                next_stage,
                match["bindings"],
                match["last_timestamp_ns"],
            ):
                continue

            match["bindings"] = bind_stage_roles(
                match["bindings"],
                next_stage,
                source_id,
                target_id,
            )
            match["next_stage_index"] += 1
            match["last_timestamp_ns"] = int(
                edge_attributes["timestamp_ns"]
            )
            match["matched_event_ids"].add(event_id)
            match["matched_stage_ids"].add(next_stage["id"])
            match["score"] += next_stage["weight"]

            candidate.match_ids_by_event.setdefault(
                event_id,
                set(),
            ).add(match_id)

            # TODO: сделаит расчет calculate_candidate_score()
            break

    # всегда проверяем может ли новое событие начать
    # новый match с первого этапа любой альтернативы
    for pattern_id, pattern in PATTERNS.items():
        for alternative in pattern["alternatives"]:
            first_stage = alternative["stages"][0]

            for source_id, target_id, _, edge_attributes in graph_edges:
                if not edge_matches_stage(
                    candidate,
                    source_id,
                    target_id,
                    edge_attributes,
                    first_stage,
                    bindings={},
                    last_timestamp_ns=None,
                ):
                    continue

                match_id = uuid4().hex
                bindings = bind_stage_roles(
                    {},
                    first_stage,
                    source_id,
                    target_id,
                )

                candidate.active_matches[match_id] = {
                    "pattern_id": pattern_id,
                    "alternative_id": alternative["id"],
                    # первый этап уже прошёл
                    "next_stage_index": 1,
                    "bindings": bindings,
                    "last_timestamp_ns": int(
                        edge_attributes["timestamp_ns"]
                    ),
                    "matched_event_ids": {event_id},
                    "matched_stage_ids": {first_stage["id"]},
                    "score": first_stage["weight"],
                    "status": "ACTIVE",
                }

                candidate.match_ids_by_event.setdefault(
                    event_id,
                    set(),
                ).add(match_id)
