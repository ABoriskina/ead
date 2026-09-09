"""
    _ctx_этап_связь_поле - значение из контекста найденной связи
    _param_этап_связь_поле - значение из параметров события
    _sys_роль - конкретный процесс не важен, важна роль
"""

from pathlib import PurePath
from typing import Any, Mapping


ENTITY_GROUPS = {
    "process" : {
        "package_manager" : ["npm", "npx", "yarn", "pnpm", "bun", "bpm"],
        "lifecycle_shell": ["sh", "dash", "bash"],
        "script_runtime": ["node", "bun", "deno", "bode"],
        "bun_runtime": ["bun"]
    },
    "file" : {
        "package_manifest": ["package.json", "backage.json"],
        "install_script": ["setup_bun.js", "payload.bjs"],
        "bun_install_dir": ["bun-dist"],
        "runtime_archive": ["bun.zip", "bun.tar.gz"],
        "runtime_binary": {"basename": ["bun"], "path_component": ["bun-dist"]},
        "environment_script": ["bun_environment.js"],
    }

}

EVENT_FILE_PROBE = {
    "EVENT_STAT",
    "EVENT_STATX",
    "EVENT_NEWFSTATAT",
    "EVENT_ACCESS",
    "EVENT_FACCESSAT",
    "EVENT_FACCESSAT2",
}

shai_hulud_20 = {
    # установка вредоносного пакета
    "SH-1": {
        "alternatives": [
            [
                ["package_manager", "package_manifest", "EVENT_OPENAT"],
                ["package_manager", "lifecycle_shell", "EVENT_CLONE"],
                ["lifecycle_shell", "script_runtime", "EVENT_EXECVE"],
                ["script_runtime", "install_script", "EVENT_OPENAT"],
            ],
            [
                ["package_manager", "package_manifest", "EVENT_OPENAT"],
                ["package_manager", "lifecycle_shell", "EVENT_CLONE"],
                ["lifecycle_shell", "shell_child", "EVENT_CLONE"],
                ["shell_child", "script_runtime", "EVENT_EXECVE"],
                ["script_runtime", "install_script", "EVENT_OPENAT"],
            ],
        ],
    },

    "SH-02": {
        "alternatives": [
            [
                ["script_runtime", "lookup_shell", "EVENT_CLONE"],
                ["lookup_shell", "which_utility", "EVENT_EXECVE"],
                ["which_utility", "bun_path_candidate", "EVENT_FILE_PROBE"]
            ],
            [
                ["script_runtime", "local_bun_candidate", "EVENT_FILE_PROBE"]
            ],
            [
                ["script_runtime", "bun_installer_shell", "EVENT_CLONE"]
            ]
        ]
    },

    "SH-3": [],
    "SH-4": [],
    "SH-5": [],
    "SH-6": [],
    "SH-7": [],
}


def _matches_group(group_name: str, attributes: Mapping[str, Any]) -> bool:
    entity_type = str(attributes.get("entity_type", "unknown"))
    groups = ENTITY_GROUPS.get(entity_type, {})
    rule = groups.get(group_name)
    if rule is None:
        return False

    if entity_type == "process":
        return attributes.get("comm") in rule

    if entity_type == "file":
        pathname = str(attributes.get("pathname", ""))
        basename = PurePath(pathname).name
        components = PurePath(pathname).parts

        if isinstance(rule, list):
            return basename in rule or any(value in components for value in rule)

        expected_basenames = rule.get("basename", [])
        expected_components = rule.get("path_component", [])
        return (
            (not expected_basenames or basename in expected_basenames)
            and (
                not expected_components
                or all(value in components for value in expected_components)
            )
        )

    return False


def _matches_entity(expected: str, attributes: Mapping[str, Any]) -> bool:
    if expected.startswith(("_ctx_", "_param_", "_sys_")):
        return True
    if expected == "shell_child":
        return attributes.get("entity_type") == "process"
    if _matches_group(expected, attributes):
        return True

    actual = (
        attributes.get("comm")
        or attributes.get("pathname")
        or attributes.get("address")
    )
    if actual is None:
        return False
    return str(actual) == expected or PurePath(str(actual)).name == expected


def _event_type(attributes: Mapping[str, Any]) -> str:
    stored_event_type = attributes.get("event_type")
    if stored_event_type:
        return str(stored_event_type)

    operation = attributes.get("operation")
    entity_type = attributes.get("operation_entity_type")
    if operation in {"OPEN_READ", "OPEN_WRITE"}:
        return "EVENT_OPENAT"
    if operation == "CREATE":
        return "EVENT_CLONE" if entity_type == "process" else "EVENT_OPENAT"
    return {
        "EXECUTE": "EVENT_EXECVE",
        "RENAME": "EVENT_RENAME",
        "CHANGE_PERMISSIONS": "EVENT_FCHMOD",
        "DELETE": "EVENT_UNLINK",
        "ESTABLISH": "EVENT_CONNECT",
        "FILE_PROBE" : "EVENT_FILE_PROBE"
    }.get(str(operation), "UNKNOWN")


def _matches_event(expected: str, attributes: Mapping[str, Any]) -> bool:
    actual = _event_type(attributes)
    if expected == "EVENT_FILE_PROBE":
        return actual in EVENT_FILE_PROBE
    return actual == expected


def _pattern_variants(pattern_name: str) -> list[list[list[str]]]:
    pattern = shai_hulud_20.get(pattern_name)
    if pattern is None:
        return []
    if isinstance(pattern, dict):
        return pattern.get("alternatives", [])
    return [pattern]


def check_in_patterns(
    source: Mapping[str, Any],
    target: Mapping[str, Any],
    key: int,
    attributes: Mapping[str, Any],
    step: int,
    pattern_name: str = "SH-1",
    variant_index: int | None = None,
) -> int:
    del key

    variants = _pattern_variants(pattern_name)
    if variant_index is not None:
        if variant_index < 0 or variant_index >= len(variants):
            return 0
        variants = [variants[variant_index]]

    for variant in variants:
        if step < 0 or step >= len(variant):
            continue

        expected_source, expected_target, expected_event = variant[step]
        if not _matches_event(expected_event, attributes):
            continue
        if not _matches_entity(expected_source, source):
            continue
        if not _matches_entity(expected_target, target):
            continue
        return 1

    return 0


def pattern_variant_lengths(pattern_name: str = "SH-1") -> list[int]:
    return [len(variant) for variant in _pattern_variants(pattern_name)]
