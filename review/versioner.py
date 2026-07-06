"""Deterministic version metadata helpers for generated rules."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from datetime import datetime, timezone
from typing import Any

from core.models import SigmaRule, WazuhRule

TOOL_NAME = "malware-behavior-detection-generator"
TOOL_VERSION = "0.1.0"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _stable_content_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sigma_hash_payload(rule: SigmaRule) -> dict[str, Any]:
    return {
        "title": rule.title,
        "rule_id": rule.rule_id,
        "description": rule.description,
        "logsource": rule.logsource,
        "detection": rule.detection,
        "level": rule.level,
        "status": rule.status,
        "author": rule.author,
        "tags": rule.tags,
        "falsepositives": rule.falsepositives,
        "fields": rule.fields,
    }


def _wazuh_hash_payload(rule: WazuhRule) -> dict[str, Any]:
    return {
        "rule_id": rule.rule_id,
        "level": rule.level,
        "description": rule.description,
        "group": rule.group,
        "decoded_as": rule.decoded_as,
        "if_sid": rule.if_sid,
        "fields": rule.fields,
        "mitre_ids": rule.mitre_ids,
    }


def version_rule(
    rule: SigmaRule | WazuhRule,
    *,
    rule_version: str = "1.0.0",
    timestamp: str | None = None,
    source_report_hash: str | None = None,
) -> SigmaRule | WazuhRule:
    """Return a copy of a rule with deterministic version metadata."""
    generated_at = timestamp or _now_iso()

    if isinstance(rule, SigmaRule):
        version_metadata = {
            "tool_name": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "rule_version": rule_version,
            "generated_at": generated_at,
            "source_report_hash": source_report_hash,
            "content_hash": _stable_content_hash(_sigma_hash_payload(rule)),
        }
        metadata = dict(rule.metadata)
        metadata["version"] = version_metadata
        return replace(rule, metadata=metadata)

    version_metadata = {
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "rule_version": rule_version,
        "generated_at": generated_at,
        "source_report_hash": source_report_hash,
        "content_hash": _stable_content_hash(_wazuh_hash_payload(rule)),
    }
    options = dict(rule.options)
    options["version"] = version_metadata
    return replace(rule, options=options)


def version_rules(
    rules: list[SigmaRule | WazuhRule] | None,
    *,
    rule_version: str = "1.0.0",
    timestamp: str | None = None,
    source_report_hash: str | None = None,
) -> list[SigmaRule | WazuhRule]:
    """Version a list of rules."""
    return [
        version_rule(
            rule,
            rule_version=rule_version,
            timestamp=timestamp,
            source_report_hash=source_report_hash,
        )
        for rule in rules or []
    ]
