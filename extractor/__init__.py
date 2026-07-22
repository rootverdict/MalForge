"""Behavior extraction package."""

from __future__ import annotations

import re
from typing import Any, Mapping

from core.models import Behavior
from core.schema import ensure_list, ensure_mapping
from extractor.file_extractor import extract_behaviors as extract_file_behaviors
from extractor.network_extractor import extract_behaviors as extract_network_behaviors
from extractor.persistence_extractor import extract_behaviors as extract_persistence_behaviors
from extractor.process_extractor import extract_behaviors as extract_process_behaviors
from extractor.registry_extractor import extract_behaviors as extract_registry_behaviors
from extractor.signature_extractor import extract_behaviors as extract_signature_behaviors

_NON_WINDOWS_MARKERS = {
    "elf",
    "linux",
    "mips",
    "arm",
    "iot",
    "router",
    "mozi",
    "gafgyt",
    "mirai",
}
_MARKER_PATTERNS = {
    "arm": r"arm(?:32|64|v[5-9](?:l)?)?",
    "elf": r"elf(?:32|64)?",
    "mips": r"mips(?:32|64)?(?:el|le)?",
}


def _contains_marker(text: str, marker: str) -> bool:
    """Match platform markers as tokens instead of filename substrings."""
    marker_pattern = _MARKER_PATTERNS.get(marker, re.escape(marker))
    return re.search(rf"(?<![A-Za-z0-9])(?:{marker_pattern})(?![A-Za-z0-9])", text) is not None


def _flatten_metadata_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        values: list[str] = []
        for nested in value.values():
            values.extend(_flatten_metadata_values(nested))
        return values
    if isinstance(value, (list, tuple, set)):
        values = []
        for nested in value:
            values.extend(_flatten_metadata_values(nested))
        return values
    return [str(value)]


def _platform_tags(normalized_report: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    sample = ensure_mapping(normalized_report.get("sample"))
    metadata = ensure_mapping(normalized_report.get("metadata"))
    values.extend(_flatten_metadata_values(sample))
    values.extend(_flatten_metadata_values(metadata.get("info")))
    values.extend(_flatten_metadata_values(metadata.get("tags")))
    for signature in ensure_list(normalized_report.get("signatures")):
        values.extend(_flatten_metadata_values(ensure_mapping(signature)))

    text = " ".join(values).lower()
    tags: list[str] = []
    if any(_contains_marker(text, marker) for marker in _NON_WINDOWS_MARKERS):
        tags.extend(["platform_non_windows", "platform_linux_or_iot"])
    if _contains_marker(text, "mips"):
        tags.append("arch_mips")
    if _contains_marker(text, "elf"):
        tags.append("format_elf")
    if _contains_marker(text, "mozi"):
        tags.append("family_mozi")
    return sorted(set(tags))


def _apply_context_tags(behaviors: list[Behavior], tags: list[str]) -> list[Behavior]:
    if not tags:
        return behaviors
    for behavior in behaviors:
        for tag in tags:
            if tag not in behavior.tags:
                behavior.tags.append(tag)
    return behaviors


def extract_behaviors(normalized_report: Mapping[str, Any]) -> list[Behavior]:
    """Aggregate behaviors from all extractor modules."""
    behaviors: list[Behavior] = []
    behaviors.extend(extract_process_behaviors(normalized_report))
    behaviors.extend(extract_registry_behaviors(normalized_report))
    behaviors.extend(extract_file_behaviors(normalized_report))
    behaviors.extend(extract_network_behaviors(normalized_report))
    behaviors.extend(extract_persistence_behaviors(normalized_report))
    behaviors.extend(extract_signature_behaviors(normalized_report))
    return _apply_context_tags(behaviors, _platform_tags(normalized_report))
