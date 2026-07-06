"""File behavior extraction from normalized sandbox reports."""

from __future__ import annotations

from typing import Any, Mapping

from core.constants import COMMON_ATTACK_MAPPINGS
from core.models import Behavior
from core.schema import ensure_list, ensure_mapping


def _file_path(item: Any) -> str:
    if isinstance(item, str):
        return item
    mapping = ensure_mapping(item)
    return str(mapping.get("path") or mapping.get("name") or "unknown_file")


def extract_behaviors(normalized_report: Mapping[str, Any]) -> list[Behavior]:
    """Extract file behaviors from a normalized report."""
    source = str(normalized_report.get("sandbox", "unknown"))
    behaviors: list[Behavior] = []

    for item in ensure_list(normalized_report.get("files")):
        path = _file_path(item)
        lowered = path.lower()
        description = f"File written: {path}"
        tags = ["file_write"]
        technique_ids = [COMMON_ATTACK_MAPPINGS["file"]["file_create"]["technique_id"]]
        severity = "medium"

        if any(token in lowered for token in ("temp", "tmp", "public", "appdata\\roaming", "appdata\\local", "programdata", "startup")):
            description = f"File dropped to user-accessible path: {path}"
            tags = ["file_drop"]
            severity = "high"

        if lowered.endswith((".dll", ".exe", ".bin")):
            tags.append("executable_artifact")

        behaviors.append(
            Behavior(
                category="file",
                description=description,
                source=source,
                severity=severity,
                evidence=[{"path": path, "raw": item}],
                tags=tags,
                technique_ids=technique_ids,
            )
        )

    return behaviors
