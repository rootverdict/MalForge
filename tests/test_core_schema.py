"""Tests for unified sandbox schema helpers."""

import json

from ingestion.cuckoo import parse_report as parse_cuckoo_report
from core.schema import (
    REQUIRED_NORMALIZED_KEYS,
    detect_sandbox,
    empty_unified_report,
    ensure_list,
    ensure_mapping,
    get_nested,
    load_json_report,
)


def test_get_nested_returns_default_for_missing_keys() -> None:
    payload = {"outer": {"inner": {"value": 42}}}

    assert get_nested(payload, "outer", "inner", "value") == 42
    assert get_nested(payload, "outer", "missing", default="fallback") == "fallback"


def test_ensure_helpers_normalize_shapes() -> None:
    assert ensure_list("item") == ["item"]
    assert ensure_list(None) == []
    assert ensure_mapping({"a": 1}) == {"a": 1}
    assert ensure_mapping(["not", "a", "mapping"]) == {}


def test_detect_sandbox_recognizes_supported_sources() -> None:
    cuckoo = {"behavior": {}, "target": {}, "signatures": []}
    cape = {"info": {"sandbox": "cape"}}
    anyrun = {"task": {"verdict": "malicious"}, "analysis": {}, "sample": {"name": "sample.exe"}}
    cape_fallback = {"info": {"version": "CAPE 2.0"}, "behavior": {"anomaly": []}}

    assert detect_sandbox(cuckoo) == "cuckoo"
    assert detect_sandbox(cape) == "cape"
    assert detect_sandbox(cape_fallback) == "cape"
    assert detect_sandbox(anyrun) == "anyrun"


def test_detect_sandbox_does_not_false_positive_anyrun_for_cuckoo_like_task_and_analysis() -> None:
    report = {
        "task": {"id": 7},
        "analysis": {},
        "behavior": {},
        "target": {"file": {"name": "sample.exe"}},
        "signatures": [],
        "info": {"sandbox": "cuckoo"},
    }

    assert detect_sandbox(report) == "cuckoo"




def test_empty_unified_report_has_expected_shape() -> None:
    empty = empty_unified_report("cape")

    assert empty["sandbox"] == "cape"
    assert empty["processes"] == []
    assert empty["metadata"] == {}
    assert tuple(empty.keys()) == REQUIRED_NORMALIZED_KEYS


def test_parsed_report_contains_required_keys_in_order() -> None:
    normalized = parse_cuckoo_report({})

    assert tuple(normalized.keys()) == REQUIRED_NORMALIZED_KEYS


def test_load_json_report_reads_object_payload(tmp_path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({"info": {"id": 99}}), encoding="utf-8")

    assert load_json_report(report_path)["info"]["id"] == 99


def test_load_json_report_accepts_utf8_bom_payload(tmp_path) -> None:
    report_path = tmp_path / "bom-report.json"
    report_path.write_text(json.dumps({"info": {"id": 100}}), encoding="utf-8-sig")

    assert load_json_report(report_path)["info"]["id"] == 100


def test_load_json_report_rejects_oversized_payload(tmp_path, monkeypatch) -> None:
    report_path = tmp_path / "large.json"
    report_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr("core.schema.MAX_REPORT_SIZE_BYTES", 1)

    try:
        load_json_report(report_path)
    except ValueError as exc:
        assert "maximum supported size" in str(exc)
    else:
        raise AssertionError("Expected oversized report to raise ValueError")
