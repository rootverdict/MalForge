"""Tests for ATT&CK mapping and Navigator layer generation."""

from __future__ import annotations

from pathlib import Path

from attck.mapper import map_behaviors_to_attack
from attck.navigator import generate_navigator_layer
from core.models import Behavior
from core.schema import load_json_report
from extractor import extract_behaviors
from ingestion.anyrun import parse_report as parse_anyrun_report
from ingestion.cape import parse_report as parse_cape_report
from ingestion.cuckoo import parse_report as parse_cuckoo_report

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _fixture_behaviors() -> list[Behavior]:
    reports = [
        parse_cuckoo_report(load_json_report(FIXTURES_DIR / "sample_cuckoo_report.json")),
        parse_cape_report(load_json_report(FIXTURES_DIR / "sample_cape_report.json")),
        parse_anyrun_report(load_json_report(FIXTURES_DIR / "sample_anyrun_report.json")),
    ]
    behaviors: list[Behavior] = []
    for report in reports:
        behaviors.extend(extract_behaviors(report))
    return behaviors


def test_process_behaviors_map_to_execution_techniques() -> None:
    mappings = map_behaviors_to_attack(
        [
            Behavior(category="process", description="Process created: helper.exe", source="cuckoo"),
            Behavior(category="process", description="Suspicious PowerShell execution", source="cuckoo"),
            Behavior(category="process", description="Suspicious command shell execution", source="cuckoo"),
        ]
    )

    pairs = {(item.technique_id, item.tactic) for item in mappings}

    assert ("T1059", "execution") in pairs
    assert ("T1059.001", "execution") in pairs
    assert ("T1059.003", "execution") in pairs


def test_persistence_behaviors_map_to_persistence_techniques() -> None:
    mappings = map_behaviors_to_attack(
        [
            Behavior(category="persistence", description="Scheduled task persistence observed", source="anyrun"),
            Behavior(category="persistence", description="Service-based persistence observed", source="anyrun"),
            Behavior(category="registry", description="Registry run key modified: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", source="anyrun"),
        ]
    )

    technique_ids = {item.technique_id for item in mappings}

    assert "T1053.005" in technique_ids
    assert "T1543.003" in technique_ids
    assert "T1547.001" in technique_ids


def test_network_behaviors_map_to_network_related_techniques() -> None:
    mappings = map_behaviors_to_attack(
        [
            Behavior(category="network", description="DNS lookup observed: api.example.test", source="cape"),
            Behavior(category="network", description="HTTP connection observed: http://example.test/health", source="cape"),
            Behavior(category="network", description="IP connection observed: 10.10.10.10", source="cape"),
            Behavior(category="network", description="IP connection observed: 110.37.53.25", source="cape", tags=["ip_connection", "non_standard_port"]),
        ]
    )

    technique_ids = {item.technique_id for item in mappings}

    assert "T1071.004" in technique_ids
    assert "T1071.001" in technique_ids
    assert "T1071" in technique_ids
    assert "T1571" in technique_ids
    assert "T1021" not in technique_ids


def test_confidence_values_are_valid_and_deduplicated() -> None:
    behaviors = [
        Behavior(category="process", description="Suspicious rundll32 execution", source="cape"),
        Behavior(category="process", description="Suspicious rundll32 execution", source="cape"),
    ]

    mappings = map_behaviors_to_attack(behaviors)

    assert len(mappings) == 1
    assert 0.0 <= mappings[0].confidence <= 1.0
    assert mappings[0].confidence >= 0.85


def test_navigator_layer_contains_expected_technique_ids() -> None:
    mappings = map_behaviors_to_attack(_fixture_behaviors())

    layer = generate_navigator_layer(mappings, name="Fixture ATT&CK Layer")
    technique_ids = {item["techniqueID"] for item in layer["techniques"]}

    assert layer["name"] == "Fixture ATT&CK Layer"
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["navigator"] == "4.9"
    assert "T1218.011" in technique_ids
    assert "T1071.004" in technique_ids
    assert "T1547.001" in technique_ids
    assert all("tactic" in item for item in layer["techniques"])


def test_empty_inputs_return_empty_results_safely() -> None:
    assert map_behaviors_to_attack([]) == []
    layer = generate_navigator_layer([])
    assert layer["techniques"] == []


def test_remote_service_mapping_is_reserved_for_explicit_remote_service_evidence() -> None:
    mappings = map_behaviors_to_attack(
        [
            Behavior(
                category="network",
                description="IP connection observed over SSH remote service: 10.0.0.5",
                source="cuckoo",
                tags=["ip_connection", "remote_service"],
            )
        ]
    )

    assert {item.technique_id for item in mappings} == {"T1021"}



def test_http_non_standard_port_maps_to_web_protocol_and_t1571() -> None:
    mappings = map_behaviors_to_attack(
        [
            Behavior(
                category="network",
                description="HTTP connection observed: http://110.37.53.25:58088/i",
                source="cuckoo",
                tags=["http_connection", "non_standard_port"],
            )
        ]
    )

    assert {item.technique_id for item in mappings} == {"T1071.001", "T1571"}
