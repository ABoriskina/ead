import json
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any


ANALYZER_PATH = Path(__file__).resolve().parent

SOURCE_CONFIG_PATH = ANALYZER_PATH / "correlation-config.json"
BUILD_PATH = ANALYZER_PATH / "build"
CONFIG_PATH = BUILD_PATH / "correlation-config.json"

SUPPORTED_OPERATIONS = {
    "process": {
        "create",
        "execute",
        "exit",
    },
    "file": {
        "open_read",
        "open_write",
        "create",
        "rename",
        "change_permissions",
        "delete",
        "execute",
    },
    "network": {
        "connect",
        "establish",
        "close",
    },
}


class CorrelationConfigError(ValueError):
    """Raised when the correlation configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class CorrelationConfig:
    time_window: float
    traversal_depth: int
    base_weights: Mapping[str, Mapping[str, float]]
    max_weights: Mapping[str, float]

    def base_weight_for(
        self,
        entity_type: str,
        operation: str,
    ) -> float:
        entity_name = entity_type.strip().lower()
        operation_name = operation.strip().lower()

        try:
            entity_weights = self.base_weights[entity_name]
        except KeyError as error:
            raise CorrelationConfigError(
                f"Unknown entity type in base_weights: {entity_type}"
            ) from error

        try:
            return entity_weights[operation_name]
        except KeyError as error:
            raise CorrelationConfigError(
                "No base weight configured for operation "
                f"{entity_type}.{operation}"
            ) from error

    def max_weight_for(self, entity_type: str) -> float:
        entity_name = entity_type.strip().lower()
        try:
            return self.max_weights[entity_name]
        except KeyError as error:
            raise CorrelationConfigError(
                f"Unknown entity type in max_weights: {entity_type}"
            ) from error

    def normalized_base_weight_for(
        self,
        entity_type: str,
        operation: str,
    ) -> float:
        base_weight = self.base_weight_for(entity_type, operation)
        max_weight = self.max_weight_for(entity_type)
        return base_weight / max_weight


def prepare_correlation_config() -> Path:
    BUILD_PATH.mkdir(parents=True, exist_ok=True)

    if not CONFIG_PATH.exists():
        shutil.copy2(SOURCE_CONFIG_PATH, CONFIG_PATH)

    return CONFIG_PATH


def load_correlation_config(
    config_path: str | Path = CONFIG_PATH,
) -> CorrelationConfig:
    path = Path(config_path)

    try:
        with path.open("r", encoding="utf-8") as config_file:
            raw_config: Any = json.load(config_file)
    except FileNotFoundError as error:
        raise CorrelationConfigError(
            f"Correlation config not found: {path}"
        ) from error
    except OSError as error:
        raise CorrelationConfigError(
            f"Cannot read correlation config {path}: {error}"
        ) from error
    except json.JSONDecodeError as error:
        raise CorrelationConfigError(
            f"Invalid JSON in correlation config {path}: "
            f"line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error

    if not isinstance(raw_config, dict):
        raise CorrelationConfigError(
            "Correlation config root must be a JSON object"
        )

    required_fields = {
        "time_window",
        "traversal_depth",
        "base_weights",
    }
    missing_fields = required_fields - raw_config.keys()
    if missing_fields:
        missing = ", ".join(sorted(missing_fields))
        raise CorrelationConfigError(
            f"Missing correlation config fields: {missing}"
        )

    unknown_fields = raw_config.keys() - required_fields
    if unknown_fields:
        unknown = ", ".join(sorted(unknown_fields))
        raise CorrelationConfigError(
            f"Unknown correlation config fields: {unknown}"
        )

    time_window = raw_config["time_window"]
    if isinstance(time_window, bool) or not isinstance(
        time_window, (int, float)
    ):
        raise CorrelationConfigError(
            "time_window must be a number of seconds"
        )
    if time_window <= 0:
        raise CorrelationConfigError(
            "time_window must be greater than zero"
        )

    traversal_depth = raw_config["traversal_depth"]
    if isinstance(traversal_depth, bool) or not isinstance(
        traversal_depth, int
    ):
        raise CorrelationConfigError(
            "traversal_depth must be an integer"
        )
    if traversal_depth <= 0:
        raise CorrelationConfigError(
            "traversal_depth must be greater than zero"
        )

    raw_base_weights = raw_config["base_weights"]
    if not isinstance(raw_base_weights, dict):
        raise CorrelationConfigError(
            "base_weights must be a JSON object"
        )

    entity_names = set(raw_base_weights)
    supported_entity_names = set(SUPPORTED_OPERATIONS)

    missing_entities = supported_entity_names - entity_names
    if missing_entities:
        missing = ", ".join(sorted(missing_entities))
        raise CorrelationConfigError(
            f"Missing base weight categories: {missing}"
        )

    unknown_entities = entity_names - supported_entity_names
    if unknown_entities:
        unknown = ", ".join(sorted(unknown_entities))
        raise CorrelationConfigError(
            f"Unknown base weight categories: {unknown}"
        )

    base_weights: dict[str, Mapping[str, float]] = {}
    max_weights: dict[str, float] = {}
    for entity_type, raw_entity_weights in raw_base_weights.items():
        if not isinstance(raw_entity_weights, dict):
            raise CorrelationConfigError(
                f"base_weights.{entity_type} must be a JSON object"
            )

        if "max_weight" not in raw_entity_weights:
            raise CorrelationConfigError(
                f"Missing max_weight for {entity_type}"
            )

        raw_max_weight = raw_entity_weights["max_weight"]
        if isinstance(raw_max_weight, bool) or not isinstance(
            raw_max_weight, (int, float)
        ):
            raise CorrelationConfigError(
                f"max_weight for {entity_type} must be a number"
            )
        if raw_max_weight <= 0:
            raise CorrelationConfigError(
                f"max_weight for {entity_type} must be greater than zero"
            )

        max_weight = float(raw_max_weight)
        operation_names = set(raw_entity_weights) - {"max_weight"}
        supported_operations = SUPPORTED_OPERATIONS[entity_type]

        missing_operations = supported_operations - operation_names
        if missing_operations:
            missing = ", ".join(sorted(missing_operations))
            raise CorrelationConfigError(
                f"Missing base weights for {entity_type}: {missing}"
            )

        unknown_operations = operation_names - supported_operations
        if unknown_operations:
            unknown = ", ".join(sorted(unknown_operations))
            raise CorrelationConfigError(
                f"Unknown operations for {entity_type}: {unknown}"
            )

        entity_weights: dict[str, float] = {}
        for operation in operation_names:
            weight = raw_entity_weights[operation]
            if isinstance(weight, bool) or not isinstance(
                weight, (int, float)
            ):
                raise CorrelationConfigError(
                    f"Base weight for {entity_type}.{operation} "
                    "must be a number"
                )
            if weight < 0:
                raise CorrelationConfigError(
                    f"Base weight for {entity_type}.{operation} "
                    "must not be negative"
                )
            if weight > max_weight:
                raise CorrelationConfigError(
                    f"Base weight for {entity_type}.{operation} "
                    f"must not exceed max_weight ({max_weight})"
                )

            entity_weights[operation] = float(weight)

        actual_max_weight = max(entity_weights.values())
        if actual_max_weight != max_weight:
            raise CorrelationConfigError(
                f"max_weight for {entity_type} is {max_weight}, "
                f"but the largest operation weight is {actual_max_weight}"
            )

        base_weights[entity_type] = MappingProxyType(entity_weights)
        max_weights[entity_type] = max_weight

    return CorrelationConfig(
        time_window=float(time_window),
        traversal_depth=traversal_depth,
        base_weights=MappingProxyType(base_weights),
        max_weights=MappingProxyType(max_weights),
    )
