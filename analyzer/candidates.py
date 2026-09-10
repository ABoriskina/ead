from dataclasses import dataclass

from .buffer import EventBuffer
from .constants import DEPTH


@dataclass(frozen=True)
class CandidateSearch:
    candidate_ids: frozenset[str]
    stop_reason: str


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

    for depth in range(max_depth + 1):
        if current_pid in visited:
            return CandidateSearch(frozenset(), "cycle")
        visited.add(current_pid)

        candidate_ids = (
            process_candidates.get((host, current_pid), set())
            & active_candidates.keys()
        )

        if candidate_ids:
            return CandidateSearch(
                frozenset(candidate_ids),
                "matched",
            )

        if depth == max_depth:
            return CandidateSearch(frozenset(), "depth_limit")

        creation = event_buffer.get_process_creation(
            host,
            current_pid,
            at_timestamp_ns=timestamp_ns,
        )

        if creation is None:
            return CandidateSearch(frozenset(), "missing_creation")

        current_pid = creation.creator_pid
        timestamp_ns = creation.timestamp_ns

    raise AssertionError("unreachable")