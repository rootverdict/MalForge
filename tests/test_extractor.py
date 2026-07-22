"""Tests for behavior extraction modules."""

from __future__ import annotations

from pathlib import Path

from core.models import Behavior
from core.schema import load_json_report
from extractor import extract_behaviors
from extractor.file_extractor import extract_behaviors as extract_file_behaviors
from extractor.network_extractor import extract_behaviors as extract_network_behaviors
from extractor.persistence_extractor import extract_behaviors as extract_persistence_behaviors
from extractor.process_extractor import extract_behaviors as extract_process_behaviors
from extractor.registry_extractor import extract_behaviors as extract_registry_behaviors
from extractor.signature_extractor import extract_behaviors as extract_signature_behaviors
from ingestion.anyrun import parse_report as parse_anyrun_report
from ingestion.cape import parse_report as parse_cape_report
from ingestion.cuckoo import parse_report as parse_cuckoo_report

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_normalized_reports() -> list[dict[str, object]]:
    return [
        parse_cuckoo_report(load_json_report(FIXTURES_DIR / "sample_cuckoo_report.json")),
        parse_cape_report(load_json_report(FIXTURES_DIR / "sample_cape_report.json")),
        parse_anyrun_report(load_json_report(FIXTURES_DIR / "sample_anyrun_report.json")),
    ]


def test_each_extractor_returns_behavior_objects() -> None:
    normalized = _load_normalized_reports()[0]

    process_behaviors = extract_process_behaviors(normalized)
    registry_behaviors = extract_registry_behaviors(normalized)
    file_behaviors = extract_file_behaviors(normalized)
    network_behaviors = extract_network_behaviors(normalized)
    persistence_behaviors = extract_persistence_behaviors(normalized)

    assert all(isinstance(item, Behavior) for item in process_behaviors)
    assert all(isinstance(item, Behavior) for item in registry_behaviors)
    assert all(isinstance(item, Behavior) for item in file_behaviors)
    assert all(isinstance(item, Behavior) for item in network_behaviors)
    assert persistence_behaviors == []


def test_missing_fields_return_empty_lists() -> None:
    empty_report = {
        "sandbox": "cuckoo",
        "processes": [],
        "registry": [],
        "files": [],
        "network": [],
        "persistence": [],
    }

    assert extract_process_behaviors(empty_report) == []
    assert extract_registry_behaviors(empty_report) == []
    assert extract_file_behaviors(empty_report) == []
    assert extract_network_behaviors(empty_report) == []
    assert extract_persistence_behaviors(empty_report) == []


def test_fixture_reports_produce_expected_category_behaviors() -> None:
    cuckoo, cape, anyrun = _load_normalized_reports()

    cuckoo_process = extract_process_behaviors(cuckoo)
    cape_process = extract_process_behaviors(cape)
    anyrun_persistence = extract_persistence_behaviors(anyrun)
    cuckoo_file = extract_file_behaviors(cuckoo)
    cuckoo_registry = extract_registry_behaviors(cuckoo)
    anyrun_network = extract_network_behaviors(anyrun)

    assert any("Process created: invoice_viewer.exe" in item.description for item in cuckoo_process)
    assert any(item.description == "Suspicious rundll32 execution" for item in cape_process)
    assert any(item.description == "Startup persistence observed" for item in anyrun_persistence)
    assert any("File dropped to user-accessible path" in item.description for item in cuckoo_file)
    assert any("Registry key modified: HKCU\\Software\\FakeApp" == item.description for item in cuckoo_registry)
    assert any("DNS lookup observed: api.example.test" == item.description for item in anyrun_network)
    assert any(item.description == "Sandbox signature observed: creates_temp_file" for item in extract_behaviors(cuckoo))


def test_aggregate_extraction_combines_all_categories() -> None:
    normalized = _load_normalized_reports()[2]

    behaviors = extract_behaviors(normalized)
    categories = {item.category for item in behaviors}

    assert categories == {"process", "registry", "file", "network", "persistence"}


def test_behavior_descriptions_are_stable_for_downstream_mapping() -> None:
    normalized = _load_normalized_reports()[1]

    descriptions = [item.description for item in extract_behaviors(normalized)]

    assert "Suspicious rundll32 execution" in descriptions
    assert "File dropped to user-accessible path: C:\\Temp\\stage.bin" in descriptions


def test_suspicious_lolbin_processes_use_specific_attack_technique_ids() -> None:
    normalized = {
        "sandbox": "cape",
        "processes": [{"process_name": "rundll32.exe", "pid": 4455, "command_line": "rundll32.exe stage.dll,Start"}],
    }

    behaviors = extract_process_behaviors(normalized)
    suspicious = next(item for item in behaviors if item.description == "Suspicious rundll32 execution")

    assert suspicious.technique_ids == ["T1218.011"]


def test_suspicious_processes_do_not_emit_duplicate_generic_process_behavior() -> None:
    normalized = {
        "sandbox": "cape",
        "processes": [{"process_name": "cmd.exe", "command_line": "cmd.exe /c whoami"}],
    }

    descriptions = [item.description for item in extract_process_behaviors(normalized)]

    assert "Suspicious command shell execution" in descriptions
    assert not any(item.startswith("Process created: cmd.exe") for item in descriptions)


def test_network_item_with_domain_and_ip_generates_multiple_behaviors() -> None:
    normalized = {"sandbox": "cape", "network": [{"domain": "example.test", "ip": "10.0.0.8"}]}

    descriptions = [item.description for item in extract_network_behaviors(normalized)]

    assert "DNS lookup observed: example.test" in descriptions
    assert "IP connection observed: 10.0.0.8" in descriptions


def test_signature_extractor_unknown_signature_returns_no_behavior() -> None:
    report = {
        "sandbox": "cuckoo",
        "signatures": [
            {"name": "totally_unknown_signature_xyz", "description": "no idea"},
            {"name": "another_unmapped_sig", "severity": 3},
        ],
    }

    assert extract_signature_behaviors(report) == []


def test_signature_extractor_known_signature_maps_conservatively() -> None:
    report = {
        "sandbox": "cuckoo",
        "signatures": [{"name": "injection", "description": "Process injection detected"}],
    }

    behaviors = extract_signature_behaviors(report)

    assert len(behaviors) >= 1
    assert behaviors[0].category == "process"
    assert behaviors[0].technique_ids
    assert behaviors[0].severity in {"medium", "high"}


def test_network_domain_field_with_raw_ip_is_not_dns_lookup() -> None:
    normalized = {"sandbox": "cuckoo", "network": [{"domain": "110.37.53.25"}]}

    behaviors = extract_network_behaviors(normalized)
    descriptions = [item.description for item in behaviors]

    assert "IP connection observed: 110.37.53.25" in descriptions
    assert not any(description.startswith("DNS lookup observed") for description in descriptions)
    assert behaviors[0].technique_ids == []

def test_ip_connection_on_non_standard_port_maps_to_t1571() -> None:
    report = {
        "sandbox": "cuckoo",
        "network": [{"ip": "110.37.53.25", "port": 58088}],
    }

    behaviors = extract_network_behaviors(report)

    assert behaviors[0].tags == ["ip_connection", "non_standard_port"]
    assert behaviors[0].technique_ids == ["T1571"]


def test_http_connection_on_non_standard_port_keeps_web_protocol_and_t1571() -> None:
    report = {
        "sandbox": "cuckoo",
        "network": [{"uri": "http://110.37.53.25:58088/i", "host": "110.37.53.25"}],
    }

    behaviors = extract_network_behaviors(report)

    assert behaviors[0].tags == ["http_connection", "non_standard_port"]
    assert behaviors[0].technique_ids == ["T1071.001", "T1571"]


def test_invalid_network_indicators_do_not_generate_behaviors() -> None:
    report = {
        "sandbox": "cuckoo",
        "network": [
            {"ip": "not-an-ip"},
            {"domain": "bad domain"},
            {"url": "not a URL"},
        ],
    }

    assert extract_network_behaviors(report) == []


def test_malformed_url_or_host_is_rejected_without_aborting_report() -> None:
    report = {
        "sandbox": "cuckoo",
        "network": [
            {"url": "http://example.test:notaport/payload"},
            {"url": "http://bad_domain/payload"},
            {"url": "http://999.999.999.999/payload"},
            {"url": "https://valid.example/payload"},
        ],
    }

    behaviors = extract_network_behaviors(report)

    assert len(behaviors) == 1
    assert behaviors[0].description == "HTTP connection observed: https://valid.example/payload"
    assert "non_standard_port" not in behaviors[0].tags


def test_ftp_url_uses_file_transfer_protocol_mapping() -> None:
    report = {
        "sandbox": "cuckoo",
        "network": [{"url": "ftp://files.example/payload"}],
    }

    behavior = extract_network_behaviors(report)[0]

    assert behavior.description == "FTP connection observed: ftp://files.example/payload"
    assert behavior.tags == ["ftp_connection"]
    assert behavior.technique_ids == ["T1071.002"]


def test_platform_markers_do_not_match_inside_windows_filename() -> None:
    report = {
        "sandbox": "cuckoo",
        "sample": {"name": "charm.exe"},
        "processes": [{"process_name": "cmd.exe", "command_line": "cmd.exe /c whoami"}],
        "metadata": {"info": {"machine": "windows-11"}},
    }

    behaviors = extract_behaviors(report)

    assert behaviors
    assert all("platform_non_windows" not in behavior.tags for behavior in behaviors)
    assert all("platform_linux_or_iot" not in behavior.tags for behavior in behaviors)


def test_suspicious_process_detection_uses_basename_for_full_paths() -> None:
    report = {
        "sandbox": "cuckoo",
        "processes": [
            {
                "image": "C:\\Windows\\System32\\cmd.exe",
                "command_line": "cmd.exe /c whoami",
            }
        ],
    }

    behaviors = extract_process_behaviors(report)

    assert len(behaviors) == 1
    assert behaviors[0].description == "Suspicious command shell execution"
    assert behaviors[0].severity == "high"
    assert "cmd" in behaviors[0].tags


def test_non_actionable_network_addresses_do_not_generate_behaviors() -> None:
    report = {
        "sandbox": "cuckoo",
        "network": [
            {"ip": "0.0.0.0"},
            {"ip": "224.0.0.1"},
            {"ipv6": "::"},
            {"ipv6": "ff02::1"},
        ],
    }

    assert extract_network_behaviors(report) == []


def test_invalid_numeric_ip_lookalike_is_not_a_domain_behavior() -> None:
    report = {"sandbox": "cuckoo", "network": [{"domain": "999.999.999.999"}]}

    assert extract_network_behaviors(report) == []


def test_smb_port_139_is_standard_but_1445_is_not() -> None:
    report = {
        "sandbox": "cuckoo",
        "network": [
            {"url": "smb://fileserver:139/share"},
            {"url": "smb://fileserver:1445/share"},
        ],
    }

    standard, non_standard = extract_network_behaviors(report)

    assert standard.tags == ["smb_connection"]
    assert standard.technique_ids == ["T1021.002"]
    assert non_standard.tags == ["smb_connection", "non_standard_port"]
    assert non_standard.technique_ids == ["T1021.002", "T1571"]


def test_tcp_non_standard_port_preserves_t1571() -> None:
    report = {
        "sandbox": "cuckoo",
        "network": [{"url": "tcp://44.55.66.99:58088"}],
    }

    behavior = extract_network_behaviors(report)[0]

    assert behavior.tags == ["tcp_connection", "non_standard_port"]
    assert behavior.technique_ids == ["T1571"]


def test_generic_network_activity_has_no_unsupported_attack_mapping() -> None:
    behavior = extract_network_behaviors({"sandbox": "cuckoo", "network": [{"bytes_sent": 42}]})[0]

    assert behavior.description == "Network activity observed"
    assert behavior.technique_ids == []


def test_common_architecture_variants_receive_non_windows_context() -> None:
    for marker in ("arm64", "mipsel", "mips64", "elf64"):
        report = {
            "sandbox": "cuckoo",
            "sample": {"name": f"sample_{marker}.bin"},
            "processes": [{"process_name": "worker", "command_line": "worker --run"}],
        }

        behavior = extract_behaviors(report)[0]

        assert "platform_non_windows" in behavior.tags
        assert "platform_linux_or_iot" in behavior.tags
        if marker.startswith("mips"):
            assert "arch_mips" in behavior.tags
        if marker.startswith("elf"):
            assert "format_elf" in behavior.tags
