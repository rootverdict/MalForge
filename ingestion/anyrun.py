"""ANY.RUN sandbox report normalization helpers."""

from __future__ import annotations

from typing import Any, Mapping

from core.schema import empty_unified_report, ensure_list, ensure_mapping, finalize_unified_report, get_nested


def _extract_sample(report: Mapping[str, Any]) -> dict[str, Any]:
    sample = ensure_mapping(report.get("sample"))
    hashes = ensure_mapping(sample.get("hashes"))
    return {
        "name": sample.get("name") or sample.get("filename") or "unknown_sample",
        "hashes": {
            "md5": sample.get("md5") or hashes.get("md5"),
            "sha1": sample.get("sha1") or hashes.get("sha1"),
            "sha256": sample.get("sha256") or hashes.get("sha256"),
        },
    }


def parse_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a raw ANY.RUN report into the unified schema."""
    normalized = empty_unified_report("anyrun")
    analysis = ensure_mapping(report.get("analysis"))
    activity = ensure_mapping(analysis.get("activity"))

    normalized["sample"] = _extract_sample(report)
    normalized["processes"] = ensure_list(
        analysis.get("processes") or activity.get("processes")
    )
    normalized["registry"] = ensure_list(activity.get("registry"))
    normalized["files"] = ensure_list(activity.get("files"))
    normalized["network"] = ensure_list(
        analysis.get("network") or activity.get("network") or report.get("network")
    )
    normalized["persistence"] = ensure_list(activity.get("persistence"))
    normalized["iocs"] = ensure_list(report.get("iocs"))
    normalized["signatures"] = ensure_list(report.get("signatures"))
    normalized["attack"] = ensure_list(report.get("attack"))
    task = ensure_mapping(report.get("task"))
    normalized["metadata"] = {
        "sandbox": "anyrun",
        "task": task,
        "analysis": analysis,
        "sandbox_verdict": task.get("verdict") or get_nested(task, "scores", "verdict"),
        "mutexes": ensure_list(activity.get("mutexes") or get_nested(report, "mutexes")),
        "raw_keys": sorted(report.keys()),
    }
    return finalize_unified_report(normalized, "anyrun")
