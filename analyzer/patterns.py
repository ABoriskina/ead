from pathlib import PurePath
from typing import Any, Mapping
from .constants import BASE_WEIGHTS, PERIODICITY

# якорные события
ENTITY_GROUPS = {
    "process" : {
        "package_manager" : ["npm", "npx", "yarn", "pnpm", "bun", "bpm"],
        "package_manager_runtime" : ["node"],
        "lifecycle_shell": ["sh", "dash", "bash"],
        "script_runtime": ["node", "bun", "deno", "bode"],
        "shell": ["sh", "dash", "bash", "zsh"],
        "git_client": ["git"],
        "secret_scanner": ["trufflehog", "gitleaks"],
        "scheduler": ["cron", "crond", "anacron"],
        "bun_runtime": ["bun"],
    },
    "file" : {
        "package_manifest": ["package.json", "backage.json"],
        "npm_config": {
            "basename": [".npmrc"],
        },
        "aws_credentials": {
            "basename": ["credentials"],
            "path_component": [".aws"],
        },
        "git_credentials": {
            "basename": [".git-credentials"],
        },
        "ssh_private_key_candidate": {
            "basename": ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"],
            "path_component": [".ssh"],
        },
        "git_hook_candidate": {
            "path_component": [".git", "hooks"],
        },
        "pypi_config": {
            "basename": [".pypirc"],
        },
        "docker_config": {
            "basename": ["config.json"],
            "path_component": [".docker"],
        },
        "environment_file_candidate": {
            "basename": [
                ".env",
                ".env.local",
                ".env.production",
                ".env.development",
                ".env.test",
            ],
        },
        "install_script": ["setup_bun.js", "payload.bjs", "postinstall.js"],
        "bun_install_dir": ["bun-dist"],
        "runtime_archive": ["bun.zip", "bun.tar.gz"],
        "runtime_binary": {"basename": ["bun"], "path_component": ["bun-dist"]},
        "environment_script": ["bun_environment.js"],
    }

}

SENSITIVE_FILE_GROUPS = frozenset({
    "aws_credentials",
    "git_credentials",
    "ssh_private_key_candidate",
    "npm_config",
    "pypi_config",
    "docker_config",
    "environment_file_candidate",
})

EVENT_FILE_PROBE = {
    "EVENT_STAT",
    "EVENT_STATX",
    "EVENT_NEWFSTATAT",
    "EVENT_ACCESS",
    "EVENT_FACCESSAT",
    "EVENT_FACCESSAT2",
}

EVENT_GROUPS = {
    "FILE_PROBE": EVENT_FILE_PROBE,
    "FILE_OPEN_ATTEMPT": {"EVENT_OPENAT"},
    "FILE_ACCESS_ATTEMPT": EVENT_FILE_PROBE | {"EVENT_OPENAT"},
    "PROCESS_EXECUTION": {"EVENT_EXECVE"},
    "PROCESS_CREATION": {"EVENT_CLONE"},
}


ANCHOR_RULES = (
    {
        "reason": "sensitive_file_access",
        "event_group": "FILE_ACCESS_ATTEMPT",
        "entity_role": "file_target",
        "entity_groups": SENSITIVE_FILE_GROUPS,
        "require_success": False,
    },
    {
        "reason": "package_manager_execution",
        "event_group": "PROCESS_EXECUTION",
        "entity_role": "executed_process",
        "entity_groups": frozenset({"package_manager"}),
        "require_success": True,
    },
    {
        "reason": "secret_scanner_execution",
        "event_group": "PROCESS_EXECUTION",
        "entity_role": "executed_process",
        "entity_groups": frozenset({"secret_scanner"}),
        "require_success": True,
    },
        {
        "reason": "scheduled_activity",
        "event_group": "PROCESS_EXECUTION",
        "entity_role": "executed_process",
        "entity_groups": frozenset({"scheduler"}),
        "require_success": False,
    },
)


# проверяем, есть ли такая группа для конкретных attributes события
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


# все совпавшие группы. совпадения на основе entity_type+comm/pathname
def entity_groups(
    attributes: Mapping[str, Any],
) -> set[str]:
    entity_type = attributes.get("entity_type", "unknown")

    return {
        group_name
        for group_name in ENTITY_GROUPS.get(entity_type, {})
        if _matches_group(group_name, attributes)
    }


# только чувствительные категории
def sensitive_file_groups(
    attributes: Mapping[str, Any],
) -> set[str]:
    return entity_groups(attributes) & SENSITIVE_FILE_GROUPS


def anchor_reasons(event: Mapping[str, Any]) -> set[str]:
    event_type = event.get("event_type", "")
    event_data = event.get("event", {})
    pathname = str(event_data.get("pathname") or "")
    categories_by_role: dict[str, set[str]] = {}

    if (
        pathname
        and event_type in EVENT_GROUPS["FILE_ACCESS_ATTEMPT"]
    ):
        categories_by_role["file_target"] = entity_groups({
            "entity_type": "file",
            "pathname": pathname,
        })

    elif (
        pathname
        and event_type in EVENT_GROUPS["PROCESS_EXECUTION"]
    ):
        categories_by_role["executed_process"] = entity_groups({
            "entity_type": "process",
            "comm": PurePath(pathname).name,
        })

    reasons: set[str] = set()

    for rule in ANCHOR_RULES:
        if event_type not in EVENT_GROUPS[rule["event_group"]]:
            continue
        if (
            rule["require_success"]
            and event_data.get("success") is not True
        ):
            print("we got anchor but it is not successfull " + pathname)
            continue

        observed_groups = categories_by_role.get(
            rule["entity_role"], set()
        )
        matched_groups = observed_groups & rule["entity_groups"]

        for group_name in matched_groups:
            reasons.add(f"{rule['reason']}:{group_name}")

    return reasons


# Для сопоставления с шаблоном
PATTERNS = {
    "SH-1": {
        "description" : "Запуск lifecycle-скрипта пакетным менеджером",
        "alternatives": [
            {
                "id": "direct-runtime",
                "stages": [
                    {
                        "id": "package_manager_execution",
                        "weight": BASE_WEIGHTS["package_manager_execution"],
                        "required": True,
                        "can_be_duplicated": False,
                        "source": {
                            "role": "launcher",
                            "entity_type": "process",
                        },
                        "edge": {
                            "event_type": "EVENT_EXECVE",
                            "operations": ["EXECUTE"],
                            "require_success": True,
                        },
                        "target": {
                            "role": "package_manager",
                            "entity_type": "process",
                            "entity_groups": ["package_manager"],
                        },
                    },
                    {
                        "id": "node_execution",
                        "weight": BASE_WEIGHTS["node_execution"],
                        "required": True,
                        "can_be_duplicated": False,
                        "source": {
                            "role": "package_manager",
                            "entity_type": "process",
                        },
                        "edge": {
                            "event_type": "EVENT_EXECVE",
                            "operations": ["EXECUTE"],
                            "require_success": True,
                        },
                        "target": {
                            "role": "package_manager_runtime",
                            "entity_type": "process",
                            "entity_groups": ["package_manager_runtime"],
                        },
                    },
                    {
                        "id": "manager_reads_manifest",
                        "weight": BASE_WEIGHTS["manager_reads_manifest"],
                        "required": True,
                        "can_be_duplicated" : False,
                        "source": {
                            "role": "package_manager_runtime",
                            "entity_type": "process",
                            "entity_groups": ["package_manager_runtime"],
                        },
                        "edge": {
                            "event_type": "EVENT_OPENAT",
                            "operations": ["OPEN_READ"],
                        },
                        "target": {
                            "role": "package_manifest",
                            "entity_type": "file",
                            "entity_groups": ["package_manifest"],
                        },
                    },
                    {
                        "id": "manager_creates_lifecycle_shell_child",
                        "weight": BASE_WEIGHTS["manager_creates_lifecycle_shell_child"],
                        "required": True,
                        "can_be_duplicated" : False,
                        "source": {
                            "role": "package_manager_runtime",
                        },
                        "edge": {
                            "event_type": "EVENT_CLONE",
                            "operations": ["CREATE"],
                        },
                        "target": {
                            "role": "lifecycle_child",
                            "entity_type": "process",
                        },
                        "within_seconds": PERIODICITY["manager_creates_lifecycle_shell_child"],
                    },
                    {
                        "id": "manager_creates_lifecycle_shell",
                        "weight": BASE_WEIGHTS["manager_creates_lifecycle_shell"],
                        "required": True,
                        "can_be_duplicated" : False,
                        "source": {
                            "role": "lifecycle_child",
                            "entity_type": "process",
                        },
                        "edge": {
                            "event_type": "EVENT_EXECVE",
                            "operations": ["EXECUTE"],
                            "require_success": True,
                        },
                        "target": {
                            "role": "lifecycle_shell",
                            "entity_type": "process",
                            "entity_groups": ["lifecycle_shell"],
                        },
                        "within_seconds": PERIODICITY["manager_creates_lifecycle_shell"],
                    },
                    {
                        "id": "shell_starts_runtime_child",
                        "weight": BASE_WEIGHTS["shell_starts_runtime_child"],
                        "required": True,
                        "can_be_duplicated" : False,
                        "source": {
                            "role": "lifecycle_shell",
                        },
                        "edge": {
                            "event_type": "EVENT_CLONE",
                            "operations": ["CREATE"],
                        },
                        "target": {
                            "role": "runtime_child",
                            "entity_type": "process",
                        },
                        "within_seconds": PERIODICITY["shell_starts_runtime_child"],
                    },
                    {
                        "id": "shell_starts_runtime",
                        "weight": BASE_WEIGHTS["shell_starts_runtime"],
                        "required": True,
                        "can_be_duplicated" : False,
                        "source": {
                            "role": "runtime_child",
                            "entity_type": "process",
                        },
                        "edge": {
                            "event_type": "EVENT_EXECVE",
                            "operations": ["EXECUTE"],
                            "require_success": True,
                        },
                        "target": {
                            "role": "script_runtime",
                            "entity_type": "process",
                            "entity_groups": ["script_runtime"],
                        },
                        "within_seconds": PERIODICITY["shell_starts_runtime"],
                    },
                    {
                        "id": "runtime_reads_install_script",
                        "weight": BASE_WEIGHTS["runtime_reads_install_script"],
                        "required": True,
                        "can_be_duplicated" : False,
                        "source": {
                            "role": "script_runtime",
                        },
                        "edge": {
                            "event_type": "EVENT_OPENAT",
                            "operations": ["OPEN_READ"],
                        },
                        "target": {
                            "role": "install_script",
                            "entity_type": "file",
                            "entity_groups": ["install_script"],
                        },
                        "within_seconds": PERIODICITY["runtime_reads_install_script"],
                    },
                ],
            },
        ],
    },

    "SH-2": {
    "description": "",
    "alternatives": [],
    },
    "SH-3": {
        "description": "",
        "alternatives": [],
    },
    "SH-4": {
        "description": "",
        "alternatives": [],
    },
    "SH-5": {
        "description": "",
        "alternatives": [],
    },
    "SH-6": {
        "description": "",
        "alternatives": [],
    },
    "SH-7": {
        "description": "",
        "alternatives": [],
    },
}


STAGE_INDEX = {
    (pattern_id, alternative["id"], stage["id"]): stage
    for pattern_id, pattern in PATTERNS.items()
    for alternative in pattern["alternatives"]
    for stage in alternative["stages"]
}


"""
  process:localhost:171699 --[EVENT_EXECVE / EXECUTE / ts=1789120947437474603]--> process:localhost:171699:exec:1789120947437474603
  process:localhost:171699:exec:1789120947437474603 --[EVENT_OPENAT / OPEN_READ / ts=1789120947438646318]--> file:/usr/lib/locale/locale-archive
    
    graph = candidate.graph.graph
    print("\nGRAPH EDGES:")
    for source, target, key, attributes in graph.edges(
        keys=True,
        data=True,
    ):
        print(
            f"  {source} "
            f"--[{attributes.get('event_type')} / "
            f"{attributes.get('operation')} / "
            f"ts={attributes.get('timestamp_ns')}]--> "
            f"{target}"
        )
"""


shai_hulud_20 = {
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


def _matches_entity(expected: str, attributes: Mapping[str, Any]) -> bool:
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


def check_in_patterns_klopik(
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
