"""Local, non-network MISP configuration helpers."""

from __future__ import annotations

from typing import Any


def build_lookup_request(indicator_type: str, value: str, url: str | None = None, api_key: str | None = None) -> dict[str, Any]:
    """Build a local-only MISP lookup descriptor without making network calls."""
    return {
        "provider": "misp",
        "enabled": bool(url and api_key),
        "indicator_type": indicator_type,
        "value": value,
        "url_configured": bool(url),
        "api_key_configured": bool(api_key),
        "network_call_performed": False,
    }
