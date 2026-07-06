"""Tests for Sigma rule generation."""

from __future__ import annotations

import uuid
from pathlib import Path

from attck.mapper import map_behaviors_to_attack
from core.models import Behavior, SigmaRule
from core.schema import load_json_report
from extractor import extract_behaviors
from generators.sigma_generator import generate_sigma_rules, rule_to_dict
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


def test_process_behavior_generates_sigma_rule() -> None:
    behavior = Behavior(
        category="process",
        description="Process created: powershell.exe (powershell.exe -nop)",
        source="cuckoo",
        evidence=[{"process_name": "powershell.exe", "command_line": "powershell.exe -nop"}],
    )
    mappings = map_behaviors_to_attack([behavior])

    rules = generate_sigma_rules([behavior], mappings)

    assert len(rules) == 1
    assert isinstance(rules[0], SigmaRule)
    assert rules[0].logsource["category"] == "process_creation"
    assert rules[0].detection["condition"] == "all of them"
    assert "Image|endswith" in rules[0].detection["selection_image"]
    assert "CommandLine|contains" in rules[0].detection["selection_cmdline"]


def test_powershell_and_cmd_behaviors_include_attack_tags() -> None:
    behaviors = [
        Behavior(
            category="process",
            description="Suspicious PowerShell execution",
            source="cape",
            evidence=[{"process_name": "powershell.exe", "command_line": "powershell.exe -enc abc"}],
        ),
        Behavior(
            category="process",
            description="Suspicious command shell execution",
            source="cape",
            evidence=[{"process_name": "cmd.exe", "command_line": "cmd.exe /c whoami"}],
        ),
    ]
    mappings = map_behaviors_to_attack(behaviors)

    rules = generate_sigma_rules(behaviors, mappings)
    tags = {tag for rule in rules for tag in rule.tags}

    assert "attack.t1059.001" in tags
    assert "attack.t1059.003" in tags


def test_registry_file_and_network_behaviors_produce_expected_logsources() -> None:
    behaviors = [
        Behavior(
            category="registry",
            description="Registry key modified: HKCU\\Software\\SafeApp",
            source="anyrun",
            evidence=[{"key": "HKCU\\Software\\SafeApp"}],
        ),
        Behavior(
            category="file",
            description="File dropped to user-accessible path: C:\\Temp\\drop.bin",
            source="anyrun",
            evidence=[{"path": "C:\\Temp\\drop.bin"}],
        ),
        Behavior(
            category="network",
            description="DNS lookup observed: api.example.test",
            source="anyrun",
            evidence=[{"domain": "api.example.test"}],
        ),
    ]

    rules = generate_sigma_rules(behaviors)
    by_category = {rule.metadata["behavior_category"]: rule for rule in rules}

    assert by_category["registry"].logsource["category"] == "registry_event"
    assert "TargetObject|contains" in by_category["registry"].detection["selection"]
    assert by_category["file"].logsource["category"] == "file_event"
    assert "TargetFilename|contains" in by_category["file"].detection["selection"]
    assert by_category["network"].logsource["category"] == "dns_query"
    assert "QueryName|contains" in by_category["network"].detection["selection"]


def test_duplicate_behaviors_do_not_create_duplicate_rules() -> None:
    behavior = Behavior(
        category="file",
        description="File dropped to user-accessible path: C:\\Temp\\stage.bin",
        source="cape",
        evidence=[{"path": "C:\\Temp\\stage.bin"}],
    )

    rules = generate_sigma_rules([behavior, behavior])

    assert len(rules) == 1


def test_empty_and_weak_behaviors_are_skipped_safely() -> None:
    behaviors = [
        Behavior(category="process", description="", source="cuckoo", evidence=[]),
        Behavior(category="network", description="Network activity observed", source="cuckoo", evidence=[{}]),
    ]

    assert generate_sigma_rules(behaviors) == []


def test_serialized_rules_are_yaml_compatible_dictionaries() -> None:
    behaviors = _fixture_behaviors()
    mappings = map_behaviors_to_attack(behaviors)

    rules = generate_sigma_rules(behaviors, mappings)
    payload = rule_to_dict(rules[0])

    assert isinstance(payload, dict)
    assert isinstance(payload["logsource"], dict)
    assert isinstance(payload["detection"], dict)
    assert payload["status"] == "experimental"
    assert "id" in payload
    assert str(uuid.UUID(payload["id"])) == payload["id"]
    assert "condition" in payload["detection"]


def test_sigma_rule_trace_metadata_exists() -> None:
    behavior = Behavior(
        category="process",
        description="Process created: invoice_viewer.exe (invoice_viewer.exe /safe)",
        source="cuckoo",
        evidence=[{"process_name": "invoice_viewer.exe", "command_line": "invoice_viewer.exe /safe"}],
        technique_ids=["T1059"],
    )
    mappings = map_behaviors_to_attack([behavior])

    rule = generate_sigma_rules([behavior], mappings)[0]
    trace = rule.metadata["trace"]

    assert trace["source_behavior_category"] == "process"
    assert trace["source_behavior_description"] == behavior.description
    assert trace["source_behavior_evidence"] == behavior.evidence
    assert "T1059" in trace["attack_technique_ids"]
    assert trace["selector_reason"]


def test_stable_rule_id_is_consistent_across_sandboxes_for_same_behavior() -> None:
    behavior_a = Behavior(
        category="process",
        description="Process created: invoice_viewer.exe",
        source="cuckoo",
        evidence=[{"process_name": "invoice_viewer.exe"}],
    )
    behavior_b = Behavior(
        category="process",
        description="Process created: invoice_viewer.exe",
        source="cape",
        evidence=[{"process_name": "invoice_viewer.exe"}],
    )

    rule_a = generate_sigma_rules([behavior_a])[0]
    rule_b = generate_sigma_rules([behavior_b])[0]

    assert rule_a.rule_id == rule_b.rule_id


def test_sigma_title_does_not_include_truncated_command_line_fragment() -> None:
    behavior = Behavior(
        category="process",
        description="Process created: powershell.exe (powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc abcdef)",
        source="cuckoo",
        evidence=[{"process_name": "powershell.exe", "command_line": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc abcdef"}],
    )

    rule = generate_sigma_rules([behavior])[0]

    assert rule.title == "Process created powershell.exe"


def test_non_windows_network_behavior_uses_linux_generic_logsource() -> None:
    behavior = Behavior(
        category="network",
        description="HTTP connection observed: http://110.37.53.25:58088/i",
        source="cuckoo",
        evidence=[{"uri": "http://110.37.53.25:58088/i", "ip": "110.37.53.25"}],
        tags=["platform_non_windows", "format_elf", "arch_mips"],
        technique_ids=["T1071.001"],
    )

    rule = generate_sigma_rules([behavior])[0]

    assert rule.logsource["product"] == "linux"
    assert rule.logsource["category"] == "network_connection"
    assert "destination.ip" in rule.detection["selection"]
    assert "url|contains" in rule.detection["selection"]
    assert "win.eventdata" not in str(rule.detection)
    assert rule.metadata["platform_context"] == "linux_or_iot"


def test_non_windows_file_behavior_uses_linux_auditd_logsource() -> None:
    behavior = Behavior(
        category="file",
        description="File dropped to user-accessible path: /tmp/mozi.m",
        source="cuckoo",
        evidence=[{"path": "/tmp/mozi.m"}],
        tags=["platform_non_windows", "format_elf"],
    )

    rule = generate_sigma_rules([behavior])[0]

    assert rule.logsource == {"category": "file_event", "product": "linux", "service": "auditd"}
    assert rule.detection["selection"] == {"file.path|contains": "mozi.m"}