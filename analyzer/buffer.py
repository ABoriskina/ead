from collections import deque
from dataclasses import dataclass
from time import monotonic
from typing import Any, Iterator
from uuid import uuid4

from .process_creation import ProcessCreation, process_creation


# стурктура для одного буферизированного события
@dataclass(frozen=True, slots=True)
class BufferedEvent:
    event_id: str
    buffered_at: float
    payload: dict[str, Any]
    process_creation: ProcessCreation | None = None


class EventBuffer:
    def __init__(self, window_seconds: float = 600.0):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.window_seconds = window_seconds
        self._events: deque[BufferedEvent] = deque()
        self._process_creations: dict[
            tuple[str, int], dict[str, ProcessCreation]
        ] = {}

    def append(self, event: dict[str, Any]) -> BufferedEvent:
        now = monotonic()
        self._evict_expired(now)

        event_id = uuid4().hex
        creation = process_creation(event, event_id)
        entry = BufferedEvent(
            event_id=event_id,
            buffered_at=now,
            payload=event,
            process_creation=creation,
        )
        self._events.append(entry)
        if creation is not None:
            key = (creation.host, creation.child_pid)
            self._process_creations.setdefault(key, {})[event_id] = creation
        return entry

    def get_process_creation(
        self, host: str, pid: int, *, at_timestamp_ns: int
    ) -> ProcessCreation | None:
        self._evict_expired(monotonic())
        records = self._process_creations.get((host, pid), {})
        return max(
            (
                record for record in records.values()
                if record.timestamp_ns <= at_timestamp_ns
            ),
            key=lambda record: record.timestamp_ns,
            default=None,
        )

    def _evict_expired(self, now: float) -> None:
        cutoff = now - self.window_seconds

        while self._events and self._events[0].buffered_at <= cutoff:
            expired = self._events.popleft()
            creation = expired.process_creation
            if creation is not None:
                key = (creation.host, creation.child_pid)
                records = self._process_creations[key]
                del records[expired.event_id]
                if not records:
                    del self._process_creations[key]

    def events(self) -> Iterator[BufferedEvent]:
        self._evict_expired(monotonic())
        return iter(self._events)

    def get_event(self, event_id: str) -> BufferedEvent | None:
        self._evict_expired(monotonic())

        for entry in self._events:
            if entry.event_id == event_id:
                return entry

        return None

    def __len__(self) -> int:
        self._evict_expired(monotonic())
        return len(self._events)
