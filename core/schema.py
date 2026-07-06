"""Unified schema helpers for safe sandbox JSON normalization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from core.constants import MAX_REPORT_SIZE_BYTES, SUPPORTED_SANDBOXES

UNIFIED_REPORT_VERSION = "1.0"
REQUIRED_NORMALIZED_KEYS = (
    "schema_version",
    "sandbox",
    "sample",
    "processes",
    "registry",
    "files",
    "network",
    "persistence",
    "iocs",
    "signatures",
    "attack",
    "metadata",
)


def load_json_report(path: str | Path) -> dict[str, Any]:
    """Load a sandbox report from disk."""
    report_path = Path(path)
    if report_path.stat().st_size > MAX_REPORT_SIZE_BYTES:
        raise ValueError(
            f"Sandbox report exceeds maximum supported size of {MAX_REPORT_SIZE_BYTES} bytes: {report_path}"
        )
    with report_path.open("r", encoding="utf-8-sig") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Sandbox report must be a JSON object")
    return data


def get_nested(data: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    """Safely retrieve a nested value from a mapping."""
    current: Any = data
    for key in keys:
        if not isinstance(current, Mapping) or key not in current:
            return default
        current = current[key]
    return current


def ensure_list(value: Any) -> list[Any]:
    """Normalize a field to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def ensure_mapping(value: Any) -> dict[str, Any]:
    """Normalize a field to a dictionary."""
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def detect_sandbox(report: Mapping[str, Any]) -> str:
    """Infer the sandbox vendor from common report markers."""
    info = ensure_mapping(report.get("info"))
    sandbox_name = str(info.get("sandbox", "")).lower()
    if sandbox_name in {"cuckoo", "cuckoo3"}:
        return "cuckoo"
    if sandbox_name == "anyrun":
        return "anyrun"
    if sandbox_name in {"cape", "capev2"}:
        return "cape"
    if "CAPE" in report or "cape" in report:
        return "cape"
    if "cape" in str(info.get("version", "")).lower():
        return "cape"
    task = ensure_mapping(report.get("task"))
    sample = ensure_mapping(report.get("sample"))
    if (
        "analysis" in report
        and task
        and (
            "uuid" in task
            or "verdict" in task
            or "scores" in task
            or bool(sample)
        )
    ):
        return "anyrun"
    if "anyrun" in str(info.get("machine", "")).lower():
        return "anyrun"
    if any(key in report for key in ("behavior", "target", "signatures")):
        return "cuckoo"
    return "unknown"


def empty_unified_report(source: str = "unknown") -> dict[str, Any]:
    """Create an empty unified report structure."""
    return {
        "schema_version": UNIFIED_REPORT_VERSION,
        "sandbox": source,
        "sample": {},
        "processes": [],
        "registry": [],
        "files": [],
        "network": [],
        "persistence": [],
        "iocs": [],
        "signatures": [],
        "attack": [],
        "metadata": {},
    }


def finalize_unified_report(normalized_report: Mapping[str, Any], source: str) -> dict[str, Any]:
    """Ensure a parser result contains the full unified schema shape."""
    finalized = dict(normalized_report)
    finalized.setdefault("schema_version", UNIFIED_REPORT_VERSION)
    finalized.setdefault("sandbox", source)
    finalized.setdefault("sample", {})
    finalized.setdefault("metadata", {})
    for key in ("processes", "registry", "files", "network", "persistence", "iocs", "signatures", "attack"):
        finalized[key] = ensure_list(finalized.get(key))
    for key in REQUIRED_NORMALIZED_KEYS:
        finalized.setdefault(key, [] if key not in {"schema_version", "sandbox", "sample", "metadata"} else {})
    finalized["schema_version"] = UNIFIED_REPORT_VERSION
    finalized["sandbox"] = source
    return finalized


def normalize_report(
    report: Mapping[str, Any],
    source: str | None = None,
) -> dict[str, Any]:
    """Normalize a sandbox report into a unified, safe schema."""
    sandbox = source or detect_sandbox(report)
    if sandbox not in SUPPORTED_SANDBOXES and sandbox != "unknown":
        raise ValueError(f"Unsupported sandbox source: {sandbox}")

    behavior = ensure_mapping(report.get("behavior"))
    summary = ensure_mapping(behavior.get("summary"))
    network = ensure_mapping(report.get("network"))
    fallback_network = report.get("network")
    if isinstance(fallback_network, Mapping):
        fallback_network = None

    normalized = empty_unified_report(sandbox)
    normalized["sample"] = ensure_mapping(report.get("target") or report.get("sample"))
    normalized["processes"] = ensure_list(
        behavior.get("processes")
        or report.get("processes")
        or get_nested(report, "analysis", "processes")
    )
    normalized["registry"] = ensure_list(summary.get("keys") or report.get("registry"))
    normalized["files"] = ensure_list(summary.get("files") or report.get("files"))
    normalized["network"] = ensure_list(
        [
            *ensure_list(network.get("hosts")),
            *ensure_list(network.get("domains")),
            *ensure_list(network.get("http")),
            *ensure_list(fallback_network),
            *ensure_list(get_nested(report, "analysis", "network")),
        ]
    )
    normalized["persistence"] = ensure_list(report.get("persistence"))
    normalized["iocs"] = ensure_list(report.get("iocs"))
    normalized["signatures"] = ensure_list(report.get("signatures"))
    normalized["attack"] = ensure_list(report.get("attack"))
    normalized["metadata"] = {
        "info": ensure_mapping(report.get("info")),
        "raw_keys": sorted(report.keys()),
    }
    return finalize_unified_report(normalized, sandbox)
