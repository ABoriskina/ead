from dataclasses import dataclass, field
from uuid import uuid4
from typing import Any

from .buffer import EventBuffer, BufferedEvent
from .correlation_config import CorrelationConfig
from .graph import EventGraph, add_event_to_graph
from .process_creation import ProcessCreation
from .constants import DEPTH


@dataclass(frozen=True)
class CandidateSearch:
    candidate_ids: frozenset[str]
    stop_reason: str
    creation_chain: tuple[ProcessCreation, ...] = ()


@dataclass
class Candidate:
    candidate_id: str
    host: str

    # причина завершения поиска при создании кандидата
    initial_search_stop: str
    graph: EventGraph = field(default_factory=EventGraph)

    # ссылки на записи сохраняют события после вытеснения из буфера
    events: dict[str, BufferedEvent] = field(default_factory=dict)

    # event_id - основания якорности.
    anchors: dict[str, set[str]] = field(default_factory=dict)

    # TODO: сделать идентификацию по start_time
    process_keys: set[tuple[str, int]] = field(default_factory=set)

    # на каком этапе каждое событие кандидата
    match_ids_by_event: dict[str, set[str]] = field(default_factory=dict)

    # описание совпадения, что ожидаем дальше и тд
    active_matches: dict[str, Any] = field(default_factory=dict)

"""
match_ids_by_event = {
    "UUID event-A": {"UUID match-1"},
    "UUID event-B": {"UUID match-1"},
    "UUID event-C": {"UUID match-1"},
    "UUID event-D": {"UUID match-1"},
}

active_matches = {
    "UUID match-1": {
        "pattern_id": "SH-1",
        "alternative_id": "direct-runtime",
        "next_stage_index": 4,
        "matched_event_ids": {
            "event-A",
            "event-B",
            "event-C",
            "event-D",
        },
        "matched_stage_ids": {
            "package_manager_execution",
            "manager_reads_manifest",
            "manager_creates_lifecycle_shell",
            "shell_starts_runtime",
        },
        "bindings": {
            "package_manager": "process:localhost:100",
            "lifecycle_shell": "process:localhost:101",
            "script_runtime": "process:localhost:102",
        },
        "score": 6.5,
    },
}
"""

# присмоединение события
def attach_event(
    candidate: Candidate,
    entry: BufferedEvent,
    *,
    reasons: set[str],
    correlation_config: CorrelationConfig,
    process_candidates: dict[tuple[str, int], set[str]],
) -> None:
    event = entry.payload
    host = event["host"]

    if host != candidate.host:
        raise ValueError("Event and candidate belong to different hosts")

    if entry.event_id not in candidate.events:
        # текущая графовая функция считает каждый EVENT_CLONE
        # созданием процесса, не передаём ей потоки и неуспешные вызовы
        is_process_creation = entry.process_creation is not None
        if event["event_type"] != "EVENT_CLONE" or is_process_creation:
            add_event_to_graph(
                event,
                correlation_config,
                candidate.graph,
                entry.event_id
            )

        candidate.events[entry.event_id] = entry

    if reasons:
        candidate.anchors.setdefault(entry.event_id, set()).update(reasons)

    process_key = (host, event["process"]["pid"])
    candidate.process_keys.add(process_key)
    process_candidates.setdefault(process_key, set()).add(
        candidate.candidate_id
    )

    # созданный процесс должен принадлежать этой цепочке
    creation = entry.process_creation
    if creation is not None:
        child_key = (host, creation.child_pid)
        candidate.process_keys.add(child_key)
        process_candidates.setdefault(child_key, set()).add(
            candidate.candidate_id
        )


def attach_creation_chain(
    candidate: Candidate,
    creation_chain: tuple[ProcessCreation, ...],
    *,
    event_buffer: EventBuffer,
    correlation_config: CorrelationConfig,
    process_candidates: dict[tuple[str, int], set[str]],
) -> list[BufferedEvent]:
    attached_entries: list[BufferedEvent] = []
    for creation in reversed(creation_chain):
        entry = event_buffer.get_event(creation.event_id)

        # если вышло по ttl
        if entry is None:
            continue
        if entry.event_id in candidate.events:
            continue
        
        attach_event(
            candidate,
            entry,
            reasons=set(),
            correlation_config=correlation_config,
            process_candidates=process_candidates,
        )
        attached_entries.append(entry)
    return attached_entries


def create_candidate(
    entry: BufferedEvent,
    *,
    reasons: set[str],
    search_stop: str,
    correlation_config: CorrelationConfig,
    active_candidates: dict[str, Candidate],
    process_candidates: dict[tuple[str, int], set[str]],
) -> Candidate:
    if not reasons:
        raise ValueError("A new candidate requires an anchor event")

    candidate = Candidate(
        candidate_id=uuid4().hex,
        host=entry.payload["host"],
        initial_search_stop=search_stop,
    )

    attach_event(
        candidate,
        entry,
        reasons=reasons,
        correlation_config=correlation_config,
        process_candidates=process_candidates,
    )

    active_candidates[candidate.candidate_id] = candidate
    return candidate


def find_related_candidates(
    *,
    host: str,
    pid: int,
    timestamp_ns: int,
    event_buffer: EventBuffer,
    process_candidates: dict[tuple[str, int], set[str]],
    active_candidates: dict,
    max_depth: int = DEPTH,
) -> CandidateSearch:
    current_pid = pid
    visited: set[int] = set()
    creation_chain: list[ProcessCreation] = []

    for depth in range(max_depth + 1):
        if current_pid in visited:
            return CandidateSearch(frozenset(), "cycle")
        visited.add(current_pid)

        # есть ли рассматриваемое событие в активных кандидатах?
        candidate_ids = (
            process_candidates.get((host, current_pid), set())
            & active_candidates.keys()
        )

        if candidate_ids:
            return CandidateSearch(
                candidate_ids=frozenset(candidate_ids),
                stop_reason="matched",
                creation_chain=tuple(creation_chain),
            )

        if depth == max_depth:
            return CandidateSearch(
                candidate_ids=frozenset(),
                stop_reason="depth_limit",
                creation_chain=tuple(creation_chain),
            )

        # есть ли событие создания рассматриваемого процесса?
        creation = event_buffer.get_process_creation(
            host,
            current_pid,
            at_timestamp_ns=timestamp_ns,
        )

        if creation is None:
            return CandidateSearch(
                candidate_ids=frozenset(),
                stop_reason="missing_creation",
                creation_chain=tuple(creation_chain),
            )

        print("Append creation chain with " + creation.event_id)
        creation_chain.append(creation)
        current_pid = creation.creator_pid
        timestamp_ns = creation.timestamp_ns

    return CandidateSearch(
        candidate_ids=frozenset(candidate_ids),
        stop_reason="matched",
        creation_chain=tuple(creation_chain),
    )
