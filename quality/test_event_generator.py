"""Synthetic local test event generation for Sigma and Wazuh rules."""

from __future__ import annotations

import hashlib

from core.models import SigmaRule, WazuhRule
from core.sigma_syntax import sigma_field_name, unescape_sigma_value

_BENIGN_FALLBACK = "benign-value"
_BENIGN_BY_FIELD = (
    (("image",), "notepad.exe"),
    (("commandline",), "notepad.exe C:\\notes.txt"),
    (("targetobject",), "HKCU\\Software\\BenignApp"),
    (("targetfilename", "file.path"), "C:\\Users\\Public\\notes.txt"),
    (("destinationip", "dstip", "destination.ip"), "127.0.0.1"),
    (("queryname", "dns.query", "query"), "localhost.localdomain"),
    (("destinationhostname", "dsthost", "destination.domain"), "localhost.localdomain"),
    (("url",), "http://localhost/benign"),
    (("exe",), "/usr/bin/cat"),
    (("cmdline", "audit.command"), "/usr/bin/cat /etc/hostname"),
)


def _negative_value(field_name: str, positive_value: str = "") -> str:
    """Pick a benign value for a field that does not collide with the observed one."""
    normalized = field_name.strip().lower()
    candidate = _BENIGN_FALLBACK
    for markers, benign in _BENIGN_BY_FIELD:
        if any(normalized.endswith(marker) or marker in normalized for marker in markers):
            candidate = benign
            break

    observed = positive_value.strip().lower()
    if not observed:
        return candidate
    # A negative event must not satisfy the selector it is meant to fail.
    if observed in candidate.lower() or candidate.lower().endswith(observed):
        digest = hashlib.sha256(observed.encode("utf-8")).hexdigest()[:8]
        return f"{_BENIGN_FALLBACK}-{digest}"
    return candidate


def generate_sigma_test_events(rule: SigmaRule) -> dict[str, list[dict[str, object]]]:
    """Generate deterministic positive and negative synthetic events for a Sigma rule."""
    selections: list[dict[str, object]] = []
    if isinstance(rule.detection, dict):
        for key, value in rule.detection.items():
            if key.startswith("selection") and isinstance(value, dict):
                selections.append(value)
    positive_event: dict[str, object] = {"event_type": rule.logsource.get("category", "unknown")}
    negative_event: dict[str, object] = {"event_type": rule.logsource.get("category", "unknown")}

    for selection in selections:
        for key, value in selection.items():
            field_name = sigma_field_name(key)
            literal_value = unescape_sigma_value(value)
            positive_event[field_name] = literal_value
            negative_event[field_name] = _negative_value(field_name, literal_value)

    return {"positive": [positive_event], "negative": [negative_event]}


def generate_wazuh_test_events(rule: WazuhRule) -> dict[str, list[dict[str, object]]]:
    """Generate deterministic positive and negative synthetic events for a Wazuh rule."""
    positive_event: dict[str, object] = {"group": rule.group, "decoder": rule.decoded_as or ""}
    negative_event: dict[str, object] = {"group": rule.group, "decoder": rule.decoded_as or ""}

    for field_name, value in rule.fields.items():
        positive_event[field_name] = value
        negative_event[field_name] = _negative_value(field_name, str(value))

    return {"positive": [positive_event], "negative": [negative_event]}


def generate_test_events(rule: SigmaRule | WazuhRule) -> dict[str, list[dict[str, object]]]:
    """Generate synthetic log-like test events for a Sigma or Wazuh rule."""
    if isinstance(rule, SigmaRule):
        return generate_sigma_test_events(rule)
    return generate_wazuh_test_events(rule)
