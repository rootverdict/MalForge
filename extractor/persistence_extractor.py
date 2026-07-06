"""Persistence behavior extraction from normalized sandbox reports."""

from __future__ import annotations

from typing import Any, Mapping

from core.constants import COMMON_ATTACK_MAPPINGS
from core.models import Behavior
from core.schema import ensure_list, ensure_mapping


def extract_behaviors(normalized_report: Mapping[str, Any]) -> list[Behavior]:
    """Extract persistence behaviors from a normalized report."""
    source = str(normalized_report.get("sandbox", "unknown"))
    behaviors: list[Behavior] = []

    for item in ensure_list(normalized_report.get("persistence")):
        persistence_item = ensure_mapping(item)
        if not persistence_item:
            continue

        persistence_type = str(persistence_item.get("type") or persistence_item.get("method") or "unknown")
        lowered = persistence_type.lower()
        description = f"Persistence mechanism observed: {persistence_type}"
        technique_ids = [COMMON_ATTACK_MAPPINGS["persistence"]["startup_folder"]["technique_id"]]
        tags = ["persistence"]

        if "task" in lowered:
            description = "Scheduled task persistence observed"
            technique_ids = [COMMON_ATTACK_MAPPINGS["persistence"]["scheduled_task"]["technique_id"]]
            tags.append("scheduled_task")
        elif "service" in lowered:
            description = "Service-based persistence observed"
            technique_ids = [COMMON_ATTACK_MAPPINGS["persistence"]["service_install"]["technique_id"]]
            tags.append("service")
        elif "startup" in lowered or "run" in lowered:
            description = "Startup persistence observed"
            technique_ids = [COMMON_ATTACK_MAPPINGS["persistence"]["startup_folder"]["technique_id"]]
            tags.append("startup")

        behaviors.append(
            Behavior(
                category="persistence",
                description=description,
                source=source,
                severity="high",
                evidence=[persistence_item],
                tags=tags,
                technique_ids=technique_ids,
            )
        )

    return behaviors
