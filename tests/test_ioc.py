"""Tests for IOC extraction modules."""

from __future__ import annotations

from pathlib import Path

from core.models import Behavior, IOC
from core.schema import load_json_report
from extractor import extract_behaviors
from ingestion.anyrun import parse_report as parse_anyrun_report
from ingestion.cape import parse_report as parse_cape_report
from ingestion.cuckoo import parse_report as parse_cuckoo_report
from ioc.ioc_extractor import (
    extract_all_iocs,
    extract_iocs_from_behaviors,
    extract_iocs_from_report,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _normalized_reports() -> list[dict[str, object]]:
    return [
        parse_cuckoo_report(load_json_report(FIXTURES_DIR / "sample_cuckoo_report.json")),
        parse_cape_report(load_json_report(FIXTURES_DIR / "sample_cape_report.json")),
        parse_anyrun_report(load_json_report(FIXTURES_DIR / "sample_anyrun_report.json")),
    ]


def test_hashes_ips_domains_and_urls_are_extracted_from_fixtures() -> None:
    cuckoo, cape, anyrun = _normalized_reports()

    cuckoo_iocs = extract_iocs_from_report(cuckoo)
    cape_iocs = extract_iocs_from_report(cape)
    anyrun_iocs = extract_iocs_from_report(anyrun)

    assert ("md5", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") in {(item.type, item.value) for item in cuckoo_iocs}
    assert ("ipv4", "44.55.66.77") in {(item.type, item.value) for item in cuckoo_iocs}
    assert ("domain", "example.test") in {(item.type, item.value) for item in cuckoo_iocs}
    assert ("url", "http://example.test/health") in {(item.type, item.value) for item in cape_iocs}
    assert ("domain", "api.example.test") in {(item.type, item.value) for item in anyrun_iocs}


def test_registry_keys_file_paths_and_mutexes_are_extracted() -> None:
    cuckoo = _normalized_reports()[0]

    iocs = extract_iocs_from_report(cuckoo)
    pairs = {(item.type, item.value) for item in iocs}

    assert ("file_path", "C:\\Users\\Public\\report.tmp") in pairs
    assert ("registry_key", "HKCU\\Software\\FakeApp") in pairs
    assert ("mutex", "SAFE-MUTEX-001") in pairs


def test_deduplication_works_across_report_and_behaviors() -> None:
    anyrun = _normalized_reports()[2]
    behaviors = extract_behaviors(anyrun)

    combined = extract_all_iocs(anyrun, behaviors)
    domains = [(item.type, item.value) for item in combined if item.type == "domain"]

    assert domains.count(("domain", "api.example.test")) == 1


def test_invalid_and_empty_values_are_ignored() -> None:
    report = {
        "sandbox": "cuckoo",
        "sample": {"hashes": {"md5": "not-a-hash", "sha1": "", "sha256": None}},
        "network": [{"ip": "999.999.999.999"}, {"domain": "bad domain"}, {"uri": "mailto:invalid"}],
        "files": [""],
        "registry": [""],
        "metadata": {"mutexes": ["", None]},
    }

    assert extract_iocs_from_report(report) == []


def test_empty_input_returns_empty_list() -> None:
    assert extract_iocs_from_report({}) == []
    assert extract_iocs_from_behaviors([]) == []
    assert extract_all_iocs({}, None) == []


def test_extraction_from_behaviors_works() -> None:
    behaviors = [
        Behavior(
            category="network",
            description="HTTP connection observed: http://portal.example.test/ping",
            source="cape",
            evidence=[{"uri": "http://portal.example.test/ping", "domain": "portal.example.test", "ip": "44.55.66.88", "ipv6": "2001:db8::10"}],
        ),
        Behavior(
            category="file",
            description="File written: C:\\Temp\\artifact.bin",
            source="cape",
            evidence=[{"path": "C:\\Temp\\artifact.bin"}],
        ),
        Behavior(
            category="registry",
            description="Registry key modified: HKCU\\Software\\SafeThing",
            source="cape",
            evidence=[{"key": "HKCU\\Software\\SafeThing"}],
        ),
    ]

    iocs = extract_iocs_from_behaviors(behaviors)
    pairs = {(item.type, item.value) for item in iocs}

    assert all(isinstance(item, IOC) for item in iocs)
    assert ("url", "http://portal.example.test/ping") in pairs
    assert ("domain", "portal.example.test") in pairs
    assert ("ipv4", "44.55.66.88") in pairs
    assert ("ipv6", "2001:db8::10") in pairs
    assert ("file_path", "C:\\Temp\\artifact.bin") in pairs
    assert ("registry_key", "HKCU\\Software\\SafeThing") in pairs


def test_raw_ip_in_domain_fields_is_ipv4_not_domain() -> None:
    report = {
        "sandbox": "cuckoo",
        "network": [
            {"domain": "110.37.53.25"},
            {"uri": "http://110.37.53.25:58088/i"},
        ],
    }
    behavior = Behavior(
        category="network",
        description="IP connection observed: 110.37.53.25",
        source="cuckoo",
        evidence=[{"domain": "110.37.53.25"}],
    )

    iocs = extract_all_iocs(report, [behavior])
    pairs = {(item.type, item.value) for item in iocs}

    assert ("ipv4", "110.37.53.25") in pairs
    assert ("domain", "110.37.53.25") not in pairs
