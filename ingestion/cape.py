"""CAPE sandbox report normalization helpers."""

from __future__ import annotations

from typing import Any, Mapping

from core.schema import empty_unified_report, ensure_list, ensure_mapping, finalize_unified_report, get_nested


def _extract_sample(report: Mapping[str, Any]) -> dict[str, Any]:
    target = ensure_mapping(report.get("target"))
    file_data = ensure_mapping(target.get("file"))
    cape_payload = ensure_mapping(report.get("CAPE"))
    return {
        "name": file_data.get("name") or cape_payload.get("payload") or "unknown_sample",
        "hashes": {
            "md5": file_data.get("md5"),
            "sha1": file_data.get("sha1"),
            "sha256": file_data.get("sha256"),
        },
    }


def parse_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a raw CAPE report into the unified schema."""
    normalized = empty_unified_report("cape")
    behavior = ensure_mapping(report.get("behavior"))
    summary = ensure_mapping(behavior.get("summary"))
    network = ensure_mapping(report.get("network"))

    normalized["sample"] = _extract_sample(report)
    normalized["processes"] = ensure_list(
        behavior.get("processes") or get_nested(report, "CAPE", "processes")
    )
    normalized["registry"] = ensure_list(summary.get("keys") or get_nested(report, "CAPE", "registry"))
    normalized["files"] = ensure_list(summary.get("files") or get_nested(report, "CAPE", "files"))
    normalized["network"] = [
        *ensure_list(network.get("hosts")),
        *ensure_list(network.get("domains")),
        *ensure_list(network.get("http")),
        *ensure_list(get_nested(report, "CAPE", "network")),
    ]
    normalized["persistence"] = ensure_list(report.get("persistence"))
    normalized["iocs"] = ensure_list(report.get("iocs"))
    normalized["signatures"] = ensure_list(report.get("signatures"))
    normalized["attack"] = ensure_list(report.get("attack"))
    normalized["metadata"] = {
        "sandbox": "cape",
        "info": ensure_mapping(report.get("info")),
        "cape": ensure_mapping(report.get("CAPE")),
        "mutexes": ensure_list(summary.get("mutexes") or get_nested(report, "CAPE", "mutexes")),
        "raw_keys": sorted(report.keys()),
    }
    return finalize_unified_report(normalized, "cape")
