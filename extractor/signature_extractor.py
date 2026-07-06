"""Signature-based behavior extraction from normalized sandbox reports."""

from __future__ import annotations

from typing import Any, Mapping

from core.constants import COMMON_ATTACK_MAPPINGS
from core.models import Behavior
from core.schema import ensure_list, ensure_mapping


def _signature_behavior(signature_name: str, source: str, raw_signature: Mapping[str, Any]) -> Behavior | None:
    normalized_name = signature_name.lower()
    if any(marker in normalized_name for marker in ("inject", "injection", "process_hollow")):
        return Behavior(
            category="process",
            description=f"Sandbox signature observed: {signature_name}",
            source=source,
            severity="high",
            evidence=[dict(raw_signature)],
            tags=["signature", "signature_process"],
            technique_ids=[COMMON_ATTACK_MAPPINGS["process"]["process_injection"]["technique_id"]],
        )
    if any(marker in normalized_name for marker in ("drop", "file", "payload")):
        return Behavior(
            category="file",
            description=f"Sandbox signature observed: {signature_name}",
            source=source,
            severity="medium",
            evidence=[dict(raw_signature)],
            tags=["signature", "signature_file"],
            technique_ids=[COMMON_ATTACK_MAPPINGS["file"]["file_create"]["technique_id"]],
        )
    if any(marker in normalized_name for marker in ("api", "network", "contact", "dns", "http")):
        return Behavior(
            category="network",
            description=f"Sandbox signature observed: {signature_name}",
            source=source,
            severity="medium",
            evidence=[dict(raw_signature)],
            tags=["signature", "signature_network"],
            technique_ids=[COMMON_ATTACK_MAPPINGS["network"]["http_beacon"]["technique_id"]],
        )
    if any(marker in normalized_name for marker in ("service", "task", "startup", "runkey", "run_key")):
        return Behavior(
            category="persistence",
            description=f"Sandbox signature observed: {signature_name}",
            source=source,
            severity="medium",
            evidence=[dict(raw_signature)],
            tags=["signature", "signature_persistence"],
            technique_ids=[COMMON_ATTACK_MAPPINGS["persistence"]["startup_folder"]["technique_id"]],
        )
    return None


def extract_behaviors(normalized_report: Mapping[str, Any]) -> list[Behavior]:
    """Extract additional behaviors from sandbox signatures."""
    source = str(normalized_report.get("sandbox", "unknown"))
    behaviors: list[Behavior] = []
    seen: set[str] = set()

    for item in ensure_list(normalized_report.get("signatures")):
        signature = ensure_mapping(item)
        signature_name = str(signature.get("name") or signature.get("description") or "").strip()
        if not signature_name or signature_name in seen:
            continue
        seen.add(signature_name)
        behavior = _signature_behavior(signature_name, source, signature)
        if behavior:
            behaviors.append(behavior)

    return behaviors
