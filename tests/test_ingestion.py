"""Tests for sandbox ingestion and normalization modules."""

from __future__ import annotations

from pathlib import Path

from core.schema import REQUIRED_NORMALIZED_KEYS, detect_sandbox, load_json_report
from ingestion.anyrun import parse_report as parse_anyrun_report
from ingestion.cape import parse_report as parse_cape_report
from ingestion.cuckoo import parse_report as parse_cuckoo_report

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_cuckoo_parser_preserves_artifacts() -> None:
    report = load_json_report(FIXTURES_DIR / "sample_cuckoo_report.json")

    normalized = parse_cuckoo_report(report)

    assert tuple(normalized.keys()) == REQUIRED_NORMALIZED_KEYS
    assert normalized["sandbox"] == "cuckoo"
    assert normalized["sample"]["name"] == "invoice_viewer.exe"
    assert normalized["processes"][0]["process_name"] == "invoice_viewer.exe"
    assert normalized["files"][0] == "C:\\Users\\Public\\report.tmp"
    assert normalized["registry"][0] == "HKCU\\Software\\FakeApp"
    assert normalized["network"][0]["ip"] == "44.55.66.77"
    assert normalized["iocs"] == []
    assert normalized["attack"] == []
    assert normalized["metadata"]["mutexes"] == ["SAFE-MUTEX-001"]


def test_cape_parser_preserves_artifacts() -> None:
    report = load_json_report(FIXTURES_DIR / "sample_cape_report.json")

    normalized = parse_cape_report(report)

    assert tuple(normalized.keys()) == REQUIRED_NORMALIZED_KEYS
    assert normalized["sandbox"] == "cape"
    assert normalized["sample"]["name"] == "document_reader.exe"
    assert normalized["processes"][0]["process_name"] == "rundll32.exe"
    assert normalized["files"][0] == "C:\\Temp\\stage.bin"
    assert normalized["registry"][0] == "HKLM\\Software\\SafeVendor"
    assert normalized["network"][0]["uri"] == "http://example.test/health"
    assert normalized["metadata"]["mutexes"] == ["SAFE-MUTEX-002"]


def test_anyrun_parser_preserves_artifacts() -> None:
    report = load_json_report(FIXTURES_DIR / "sample_anyrun_report.json")

    normalized = parse_anyrun_report(report)

    assert tuple(normalized.keys()) == REQUIRED_NORMALIZED_KEYS
    assert normalized["sandbox"] == "anyrun"
    assert normalized["sample"]["name"] == "media_helper.exe"
    assert normalized["processes"][0]["name"] == "media_helper.exe"
    assert normalized["files"][0]["path"] == "C:\\Users\\Public\\media.log"
    assert normalized["registry"][0]["key"] == "HKCU\\Software\\SafeMedia"
    assert normalized["network"][0]["domain"] == "api.example.test"
    assert normalized["metadata"]["mutexes"] == ["SAFE-MUTEX-003"]
    assert normalized["metadata"]["sandbox_verdict"] == "suspicious"


def test_missing_fields_do_not_crash_any_parser() -> None:
    assert parse_cuckoo_report({})["processes"] == []
    assert parse_cape_report({"info": {"sandbox": "cape"}})["files"] == []
    assert parse_anyrun_report({"task": {}})["network"] == []


def test_detect_sandbox_matches_fixture_shapes() -> None:
    cuckoo_report = load_json_report(FIXTURES_DIR / "sample_cuckoo_report.json")
    cape_report = load_json_report(FIXTURES_DIR / "sample_cape_report.json")
    anyrun_report = load_json_report(FIXTURES_DIR / "sample_anyrun_report.json")

    assert detect_sandbox(cuckoo_report) == "cuckoo"
    assert detect_sandbox(cape_report) == "cape"
    assert detect_sandbox(anyrun_report) == "anyrun"


def test_batch_loading_parses_all_supported_fixtures() -> None:
    fixture_map = {
        "sample_cuckoo_report.json": parse_cuckoo_report,
        "sample_cape_report.json": parse_cape_report,
        "sample_anyrun_report.json": parse_anyrun_report,
    }

    parsed = []
    for fixture_name, parser in fixture_map.items():
        report = load_json_report(FIXTURES_DIR / fixture_name)
        parsed.append(parser(report))

    assert [item["sandbox"] for item in parsed] == ["cuckoo", "cape", "anyrun"]
    assert all(tuple(item.keys()) == REQUIRED_NORMALIZED_KEYS for item in parsed)


def test_cuckoo_parser_preserves_http_network_entries_with_domains() -> None:
    report = {
        "info": {"id": 1},
        "target": {"file": {"name": "sample"}},
        "network": {
            "domains": [{"domain": "110.37.53.25"}],
            "http": [{"uri": "http://110.37.53.25:58088/i", "host": "110.37.53.25"}],
        },
    }

    normalized = parse_cuckoo_report(report)

    assert {"domain": "110.37.53.25"} in normalized["network"]
    assert {"uri": "http://110.37.53.25:58088/i", "host": "110.37.53.25"} in normalized["network"]
