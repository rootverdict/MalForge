"""Deterministic-friendly time helpers shared across pipeline stages."""

from __future__ import annotations

from datetime import datetime, timezone


def now_iso() -> str:
    """Return the current UTC time as a second-precision ISO-8601 string."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
