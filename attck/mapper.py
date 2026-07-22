"""Rule-based ATT&CK mapping for extracted behaviors."""

from __future__ import annotations

from typing import Iterable

from core.constants import COMMON_ATTACK_MAPPINGS
from core.models import AttackMapping, Behavior


def _mapping_entry(category: str, key: str) -> dict[str, str]:
    return COMMON_ATTACK_MAPPINGS[category][key]


def _build_mapping(
    behavior: Behavior,
    technique: dict[str, str],
    confidence: float,
) -> AttackMapping:
    return AttackMapping(
        technique_id=technique["technique_id"],
        technique_name=technique["technique_name"],
        tactic=technique["tactic"],
        source_behavior=behavior.description,
        confidence=confidence,
        evidence=behavior.evidence,
    )


def _map_process_behavior(behavior: Behavior) -> list[AttackMapping]:
    description = behavior.description.lower()
    mappings: list[AttackMapping] = []

    explicit_patterns = (
        (("powershell",), _mapping_entry("process", "powershell")),
        (("cmd", "command shell"), _mapping_entry("process", "cmd")),
        (("rundll32",), _mapping_entry("process", "rundll32")),
        (("regsvr32",), _mapping_entry("process", "regsvr32")),
        (("mshta",), _mapping_entry("process", "mshta")),
    )
    for markers, technique in explicit_patterns:
        if any(marker in description for marker in markers):
            mappings.append(_build_mapping(behavior, technique, 0.95))

    if not mappings:
        mappings.append(_build_mapping(behavior, _mapping_entry("process", "process_create"), 0.7))

    return mappings


def _map_registry_behavior(behavior: Behavior) -> list[AttackMapping]:
    description = behavior.description.lower()
    if "run key" in description:
        return [_build_mapping(behavior, _mapping_entry("registry", "run_key"), 0.9)]
    return [_build_mapping(behavior, _mapping_entry("registry", "registry_modification"), 0.7)]


def _map_file_behavior(behavior: Behavior) -> list[AttackMapping]:
    description = behavior.description.lower()
    evidence_text = " ".join(str(value).lower() for item in behavior.evidence for value in item.values() if value is not None)
    if any(token in evidence_text for token in ("\\run", "\\startup", "startup")):
        return [_build_mapping(behavior, _mapping_entry("registry", "run_key"), 0.75)]
    if "drop" in description or "executable_artifact" in behavior.tags:
        return [_build_mapping(behavior, _mapping_entry("file", "file_create"), 0.65)]
    return [_build_mapping(behavior, _mapping_entry("file", "file_create"), 0.5)]


def _map_network_behavior(behavior: Behavior) -> list[AttackMapping]:
    description = behavior.description.lower()
    tags = set(behavior.tags)
    if "dns lookup" in description:
        return [_build_mapping(behavior, _mapping_entry("network", "dns_query"), 0.9)]
    if "http connection" in description:
        mappings = [_build_mapping(behavior, _mapping_entry("network", "http_beacon"), 0.9)]
        if "non_standard_port" in tags:
            mappings.append(_build_mapping(behavior, _mapping_entry("network", "non_standard_port"), 0.8))
        return mappings
    if "ftp_connection" in tags or "ftp connection" in description:
        mappings = [_build_mapping(behavior, _mapping_entry("network", "file_transfer_protocol"), 0.9)]
        if "non_standard_port" in tags:
            mappings.append(_build_mapping(behavior, _mapping_entry("network", "non_standard_port"), 0.8))
        return mappings
    if "smb_connection" in tags or "smb connection" in description:
        mappings = [_build_mapping(behavior, _mapping_entry("network", "smb"), 0.9)]
        if "non_standard_port" in tags:
            mappings.append(_build_mapping(behavior, _mapping_entry("network", "non_standard_port"), 0.8))
        return mappings
    if "tcp_connection" in tags or "tcp connection" in description:
        mappings: list[AttackMapping] = []
        if "non_standard_port" in tags:
            mappings.append(_build_mapping(behavior, _mapping_entry("network", "non_standard_port"), 0.8))
        return mappings
    if "ip connection" in description:
        mappings = []
        if "remote_service" in tags or any(token in description for token in ("rdp", "ssh", "smb", "winrm", "remote service")):
            mappings.append(_build_mapping(behavior, _mapping_entry("network", "remote_service"), 0.75))
        if "non_standard_port" in tags:
            mappings.append(_build_mapping(behavior, _mapping_entry("network", "non_standard_port"), 0.8))
        return mappings
    return []


def _map_persistence_behavior(behavior: Behavior) -> list[AttackMapping]:
    description = behavior.description.lower()
    if "scheduled task" in description:
        return [_build_mapping(behavior, _mapping_entry("persistence", "scheduled_task"), 0.95)]
    if "service" in description:
        return [_build_mapping(behavior, _mapping_entry("persistence", "service_install"), 0.95)]
    if "startup" in description or "run key" in description:
        return [_build_mapping(behavior, _mapping_entry("persistence", "startup_folder"), 0.85)]
    return [_build_mapping(behavior, _mapping_entry("persistence", "startup_folder"), 0.5)]


def _deduplicate_mappings(mappings: Iterable[AttackMapping]) -> list[AttackMapping]:
    deduped: list[AttackMapping] = []
    seen: set[tuple[str, str]] = set()
    for mapping in mappings:
        key = (mapping.source_behavior, mapping.technique_id)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(mapping)
    return deduped


def map_behaviors_to_attack(behaviors: list[Behavior] | None) -> list[AttackMapping]:
    """Map extracted behaviors to ATT&CK techniques."""
    if not behaviors:
        return []

    collected: list[AttackMapping] = []
    for behavior in behaviors:
        if behavior.category == "process":
            collected.extend(_map_process_behavior(behavior))
        elif behavior.category == "registry":
            collected.extend(_map_registry_behavior(behavior))
        elif behavior.category == "file":
            collected.extend(_map_file_behavior(behavior))
        elif behavior.category == "network":
            collected.extend(_map_network_behavior(behavior))
        elif behavior.category == "persistence":
            collected.extend(_map_persistence_behavior(behavior))

    return _deduplicate_mappings(collected)


