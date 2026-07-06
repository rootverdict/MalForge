"""Local, non-network VirusTotal configuration helpers."""

from __future__ import annotations

from typing import Any


def build_lookup_request(indicator_type: str, value: str, api_key: str | None = None) -> dict[str, Any]:
    """Build a local-only VirusTotal lookup descriptor without making network calls."""
    return {
        "provider": "virustotal",
        "enabled": bool(api_key),
        "indicator_type": indicator_type,
        "value": value,
        "api_key_configured": bool(api_key),
        "network_call_performed": False,
    }
