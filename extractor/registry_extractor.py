"""Registry behavior extraction from normalized sandbox reports."""

from __future__ import annotations

from typing import Any, Mapping

from core.constants import COMMON_ATTACK_MAPPINGS
from core.models import Behavior
from core.schema import ensure_list, ensure_mapping


def _registry_key(item: Any) -> str:
    if isinstance(item, str):
        return item
    mapping = ensure_mapping(item)
    return str(mapping.get("key") or mapping.get("path") or "unknown_registry_key")


def extract_behaviors(normalized_report: Mapping[str, Any]) -> list[Behavior]:
    """Extract registry behaviors from a normalized report."""
    source = str(normalized_report.get("sandbox", "unknown"))
    behaviors: list[Behavior] = []

    for item in ensure_list(normalized_report.get("registry")):
        key = _registry_key(item)
        lowered = key.lower()
        tags = ["registry_set"]
        technique_ids = [COMMON_ATTACK_MAPPINGS["registry"]["registry_modification"]["technique_id"]]
        description = f"Registry key modified: {key}"

        if "\\run" in lowered or "\\runonce" in lowered:
            tags = ["registry_run_key", "persistence"]
            technique_ids = [COMMON_ATTACK_MAPPINGS["registry"]["run_key"]["technique_id"]]
            description = f"Registry run key modified: {key}"

        behaviors.append(
            Behavior(
                category="registry",
                description=description,
                source=source,
                severity="medium",
                evidence=[{"key": key, "raw": item}],
                tags=tags,
                technique_ids=technique_ids,
            )
        )

    return behaviors
