from dataclasses import dataclass
from typing import Any, Mapping


# Linux UAPI clone flags; parent_tid/child_tid in the event are user pointers.
CLONE_PARENT = 0x00008000
CLONE_THREAD = 0x00010000


@dataclass(frozen=True, slots=True)
class ProcessCreation:
    event_id: str
    host: str
    creator_pid: int
    creator_tid: int
    child_pid: int
    parent_pid: int | None
    timestamp_ns: int
    syscall_type: int
    clone_flags: int


def _integer(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    try:
        return int(value)
    except ValueError:
        return None


def process_creation(
    event: Mapping[str, Any], event_id: str
) -> ProcessCreation | None:
    if event.get("event_type") != "EVENT_CLONE":
        return None

    data = event.get("event", {})
    process = event.get("process", {})
    if not isinstance(data, Mapping) or not isinstance(process, Mapping):
        return None
    if data.get("success") is not True:
        return None

    creator_pid = _integer(process.get("pid"))
    creator_tid = _integer(process.get("tid"))
    child_pid = _integer(data.get("created_task_id"))
    result = _integer(data.get("result"))
    flags = _integer(data.get("clone_flags"))
    timestamp_ns = _integer(data.get("timestamp_ns"))
    syscall_type = _integer(data.get("syscall_type"))

    if any(value is None or value <= 0 for value in (
        creator_pid, creator_tid, child_pid, timestamp_ns
    )):
        return None
    if flags is None or flags < 0 or syscall_type is None or syscall_type < 0:
        return None
    if result != child_pid or flags & CLONE_THREAD or creator_pid == child_pid:
        return None

    return ProcessCreation(
        event_id=event_id,
        host=str(event.get("host") or "unknown"),
        creator_pid=creator_pid,
        creator_tid=creator_tid,
        child_pid=child_pid,
        # CLONE_PARENT makes the caller a sibling, not the child's parent.
        parent_pid=None if flags & CLONE_PARENT else creator_pid,
        timestamp_ns=timestamp_ns,
        syscall_type=syscall_type,
        clone_flags=flags,
    )
