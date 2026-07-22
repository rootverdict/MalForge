"""Tests for Sigma to Wazuh conversion."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from attck.mapper import map_behaviors_to_attack
import converters.wazuh_converter as wazuh_converter
from converters.wazuh_converter import (
    convert_sigma_to_wazuh,
    wazuh_rule_to_xml,
    wazuh_rules_to_xml,
)
import pytest

from core.constants import SIGMA_TO_WAZUH_LEVEL, WAZUH_CUSTOM_RULE_ID_RANGE
from core.models import Behavior, SigmaRule, WazuhRule
from core.schema import load_json_report
from extractor import extract_behaviors
from generators.sigma_generator import generate_sigma_rules
from ingestion.anyrun import parse_report as parse_anyrun_report
from ingestion.cape import parse_report as parse_cape_report
from ingestion.cuckoo import parse_report as parse_cuckoo_report

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _fixture_sigma_rules() -> list[SigmaRule]:
    reports = [
        parse_cuckoo_report(load_json_report(FIXTURES_DIR / "sample_cuckoo_report.json")),
        parse_cape_report(load_json_report(FIXTURES_DIR / "sample_cape_report.json")),
        parse_anyrun_report(load_json_report(FIXTURES_DIR / "sample_anyrun_report.json")),
    ]
    behaviors: list[Behavior] = []
    for report in reports:
        behaviors.extend(extract_behaviors(report))
    mappings = map_behaviors_to_attack(behaviors)
    return generate_sigma_rules(behaviors, mappings)


def _dns_sigma_rule(rule_id: str = "sigma-dns-test") -> SigmaRule:
    return SigmaRule(
        title="DNS Test Rule",
        rule_id=rule_id,
        description="DNS query observed",
        logsource={"category": "dns_query", "product": "windows"},
        detection={"selection": {"QueryName|contains": "example.test"}, "condition": "selection"},
    )


def test_sigma_process_rule_converts_to_wazuh_rule() -> None:
    sigma_rule = SigmaRule(
        title="Process Created Powershell Exe",
        rule_id="sigma-123456789abc",
        description="Process created: powershell.exe",
        logsource={"category": "process_creation", "product": "windows"},
        detection={"selection": {"Image|endswith": "powershell.exe"}, "condition": "selection"},
        level="high",
        tags=["attack.t1059.001"],
    )

    rules = convert_sigma_to_wazuh([sigma_rule])

    assert len(rules) == 1
    assert isinstance(rules[0], WazuhRule)
    assert rules[0].group == "sysmon,process_creation,"
    assert rules[0].if_sid == 61603
    assert rules[0].decoded_as is None
    assert rules[0].fields["win.eventdata.image"] == "powershell.exe"


def test_wazuh_ids_are_deterministic_and_in_range() -> None:
    sigma_rule = SigmaRule(
        title="Registry SafeApp",
        rule_id="sigma-deadbeef0001",
        description="Registry key modified: HKCU\\Software\\SafeApp",
        logsource={"category": "registry_event", "product": "windows"},
        detection={"selection": {"TargetObject|contains": "HKCU\\Software\\SafeApp"}, "condition": "selection"},
        level="medium",
    )

    first = convert_sigma_to_wazuh([sigma_rule])[0]
    second = convert_sigma_to_wazuh([sigma_rule])[0]

    assert first.rule_id == second.rule_id
    assert first.rule_id in WAZUH_CUSTOM_RULE_ID_RANGE


def test_severity_mapping_works() -> None:
    sigma_rule = SigmaRule(
        title="Network Query",
        rule_id="sigma-000000000001",
        description="DNS lookup observed: api.example.test",
        logsource={"category": "dns_query", "product": "windows"},
        detection={"selection": {"QueryName|contains": "api.example.test"}, "condition": "selection"},
        level="critical",
    )

    converted = convert_sigma_to_wazuh([sigma_rule])[0]

    assert converted.level == SIGMA_TO_WAZUH_LEVEL["critical"]


def test_attack_tags_are_preserved_in_xml_and_metadata() -> None:
    sigma_rule = SigmaRule(
        title="Suspicious PowerShell",
        rule_id="sigma-attack-001",
        description="Suspicious PowerShell execution",
        logsource={"category": "process_creation", "product": "windows"},
        detection={"selection": {"Image|endswith": "powershell.exe"}, "condition": "selection"},
        level="high",
        tags=["attack.t1059.001", "attack.t1059"],
    )

    converted = convert_sigma_to_wazuh([sigma_rule])[0]
    xml_text = wazuh_rule_to_xml(converted)
    root = ET.fromstring(xml_text)
    mitre_ids = [item.text for item in root.findall("./mitre/id")]

    assert converted.mitre_ids == ["T1059", "T1059.001"]
    assert "T1059.001" in mitre_ids


def test_xml_output_is_parseable() -> None:
    converted = convert_sigma_to_wazuh(_fixture_sigma_rules())
    xml_text = wazuh_rules_to_xml(converted)
    root = ET.fromstring(xml_text)

    assert root.tag == "group"
    assert len(root.findall("./rule")) == len(converted)
    assert "\n" in xml_text


def test_xml_output_does_not_emit_options_element() -> None:
    converted = convert_sigma_to_wazuh(_fixture_sigma_rules())

    single_xml = wazuh_rule_to_xml(converted[0])
    group_xml = wazuh_rules_to_xml(converted)

    assert "<options>" not in single_xml
    assert "<options>" not in group_xml
    ET.fromstring(single_xml)
    ET.fromstring(group_xml)


def test_registry_and_file_paths_are_escaped_for_wazuh_regex_match_values() -> None:
    sigma_rules = [
        SigmaRule(
            title="Registry SafeApp",
            rule_id="sigma-registry-path",
            description="Registry key modified: HKCU\\Software\\FakeApp",
            logsource={"category": "registry_event", "product": "windows"},
            detection={"selection": {"TargetObject|contains": "HKCU\\Software\\FakeApp"}, "condition": "selection"},
            level="medium",
        ),
        SigmaRule(
            title="Dropped Report Temp File",
            rule_id="sigma-file-path",
            description="File dropped to user-accessible path: C:\\Users\\Public\\report.tmp",
            logsource={"category": "file_event", "product": "windows"},
            detection={"selection": {"TargetFilename|contains": "C:\\Users\\Public\\report.tmp"}, "condition": "selection"},
            level="high",
        ),
    ]

    converted = convert_sigma_to_wazuh(sigma_rules)
    xml_text = wazuh_rules_to_xml(converted)
    root = ET.fromstring(xml_text)

    field_values = [field.text or "" for field in root.findall(".//field")]

    assert r"(?i)HKCU\\Software\\FakeApp" in field_values
    assert r"(?i)C:\\Users\\Public\\report\.tmp" in field_values


def test_xml_contains_structured_field_names_for_decoded_rules() -> None:
    converted = convert_sigma_to_wazuh(_fixture_sigma_rules())
    xml_text = wazuh_rules_to_xml(converted)

    assert "win.eventdata.targetObject" in xml_text
    assert "win.eventdata.targetFilename" in xml_text
    assert "win.eventdata.queryName" in xml_text
    ET.fromstring(xml_text)


def test_registry_file_ip_and_dns_use_fields_while_process_uses_sysmon_parent() -> None:
    sigma_rules = [
        SigmaRule(
            title="Process Command Line",
            rule_id="sigma-process-match",
            description="Process created: cmd.exe (/c whoami)",
            logsource={"category": "process_creation", "product": "windows"},
            detection={"selection": {"CommandLine|contains": "cmd.exe /c whoami"}, "condition": "selection"},
            level="high",
        ),
        SigmaRule(
            title="Registry Path",
            rule_id="sigma-registry-match",
            description="Registry key modified: HKCU\\Software\\FakeApp",
            logsource={"category": "registry_event", "product": "windows"},
            detection={"selection": {"TargetObject|contains": "HKCU\\Software\\FakeApp"}, "condition": "selection"},
            level="medium",
        ),
        SigmaRule(
            title="File Path",
            rule_id="sigma-file-match",
            description="File written: C:\\Users\\Public\\report.tmp",
            logsource={"category": "file_event", "product": "windows"},
            detection={"selection": {"TargetFilename|contains": "C:\\Users\\Public\\report.tmp"}, "condition": "selection"},
            level="high",
        ),
        SigmaRule(
            title="IP Match",
            rule_id="sigma-ip-match",
            description="IP connection observed: 10.10.10.10",
            logsource={"category": "network_connection", "product": "windows"},
            detection={"selection": {"DestinationIp": "10.10.10.10"}, "condition": "selection"},
            level="medium",
        ),
        SigmaRule(
            title="DNS Match",
            rule_id="sigma-dns-match",
            description="DNS lookup observed: example.test",
            logsource={"category": "dns_query", "product": "windows"},
            detection={"selection": {"QueryName|contains": "example.test"}, "condition": "selection"},
            level="medium",
        ),
    ]

    converted = convert_sigma_to_wazuh(sigma_rules)
    xml_text = wazuh_rules_to_xml(converted)
    root = ET.fromstring(xml_text)

    process_rule = root.findall("./rule")[0]
    assert process_rule.find("./field[@name='win.eventdata.image']") is None
    assert process_rule.find("./field[@name='win.eventdata.commandLine']") is not None
    assert process_rule.find("./match") is None
    assert root.find(".//field[@name='win.eventdata.targetObject']") is not None
    assert root.find(".//field[@name='win.eventdata.targetFilename']") is not None
    assert root.find(".//field[@name='win.eventdata.destinationIp']") is not None
    assert root.find(".//field[@name='win.eventdata.queryName']") is not None


def test_generated_xml_shape_matches_wazuh_lab_constraints() -> None:
    converted = convert_sigma_to_wazuh(_fixture_sigma_rules())
    xml_text = wazuh_rules_to_xml(converted)
    root = ET.fromstring(xml_text)

    assert root.attrib["name"] == "malware_behavior_detection_generator,"
    assert "<if_sid>80700</if_sid>" not in xml_text
    assert "<decoded_as>json</decoded_as>" not in xml_text
    assert "<if_group>sysmon_event" in xml_text
    assert "<options>" not in xml_text
    rule_groups = [element.text or "" for element in root.findall("./rule/group")]
    assert rule_groups
    assert all(group.endswith(",") for group in rule_groups)
    rules = root.findall("./rule")
    assert rules
    assert any(rule.findall("./field") for rule in rules)
    assert not root.findall(".//match")


def test_process_creation_rule_uses_live_tested_sysmon_shape() -> None:
    sigma_rule = SigmaRule(
        title="Invoice Viewer Process",
        rule_id="sigma-live-shape-001",
        description="Process created: invoice_viewer.exe (invoice_viewer.exe /safe)",
        logsource={"category": "process_creation", "product": "windows"},
        detection={
            "selection": {
                "Image|endswith": "invoice_viewer.exe",
                "CommandLine|contains": "invoice_viewer.exe /safe",
            },
            "condition": "selection",
        },
        level="medium",
        tags=["attack.t1059"],
    )

    converted = convert_sigma_to_wazuh([sigma_rule])[0]
    xml_text = wazuh_rule_to_xml(converted)
    root = ET.fromstring(xml_text)

    assert "<if_sid>61603</if_sid>" in xml_text
    assert r'<field name="win.eventdata.image" type="pcre2">(?i)invoice_viewer\.exe$</field>' in xml_text
    assert '<field name="win.eventdata.commandLine" type="pcre2">(?i)invoice_viewer\\.exe /safe</field>' in xml_text
    assert "<decoded_as>" not in xml_text
    assert "<match>" not in xml_text
    assert root.find("./if_sid") is not None
    assert root.find("./field[@name='win.eventdata.image']") is not None
    assert root.find("./field[@name='win.eventdata.commandLine']") is not None
    child_tags = [child.tag for child in root]
    assert child_tags[:5] == ["if_sid", "field", "field", "description", "group"]


def test_wazuh_rule_trace_metadata_exists() -> None:
    sigma_rule = SigmaRule(
        title="Invoice Viewer Process",
        rule_id="sigma-trace-001",
        description="Process created: invoice_viewer.exe (invoice_viewer.exe /safe)",
        logsource={"category": "process_creation", "product": "windows"},
        detection={
            "selection": {
                "Image|endswith": "invoice_viewer.exe",
                "CommandLine|contains": "invoice_viewer.exe /safe",
            },
            "condition": "selection",
        },
        level="medium",
        tags=["attack.t1059"],
        metadata={
            "trace": {
                "source_behavior_category": "process",
                "source_behavior_description": "Process created: invoice_viewer.exe (invoice_viewer.exe /safe)",
                "source_behavior_evidence": [{"process_name": "invoice_viewer.exe"}],
                "attack_technique_ids": ["T1059"],
                "selector_reason": "Process selector chosen from executable and command line evidence.",
            }
        },
    )

    converted = convert_sigma_to_wazuh([sigma_rule])[0]
    trace = converted.options["trace"]

    assert trace["source_sigma_rule_id"] == "sigma-trace-001"
    assert "61603" in trace["conversion_reason"]
    assert trace["source_sigma_trace"]["source_behavior_category"] == "process"


def test_wazuh_rule_id_exhaustion_raises_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wazuh_converter, "WAZUH_CUSTOM_RULE_ID_RANGE", range(100000, 100002))
    monkeypatch.setattr(wazuh_converter, "WAZUH_RULE_ID_START", 100000)
    sigma_rules = [
        SigmaRule(
            title=f"Rule {index}",
            rule_id=f"sigma-exhaust-{index}",
            description=f"Rule {index}",
            logsource={"category": "dns_query", "product": "windows"},
            detection={"selection": {"QueryName|contains": f"example{index}.test"}, "condition": "selection"},
            level="medium",
        )
        for index in range(3)
    ]

    with pytest.raises(ValueError, match="ID space exhausted"):
        convert_sigma_to_wazuh(sigma_rules)


def test_duplicate_sigma_rules_do_not_create_duplicate_wazuh_rules() -> None:
    sigma_rule = SigmaRule(
        title="Duplicate File Rule",
        rule_id="sigma-dup-001",
        description="File dropped to user-accessible path: C:\\Temp\\stage.bin",
        logsource={"category": "file_event", "product": "windows"},
        detection={"selection": {"TargetFilename|contains": "C:\\Temp\\stage.bin"}, "condition": "selection"},
        level="high",
    )

    converted = convert_sigma_to_wazuh([sigma_rule, sigma_rule])

    assert len(converted) == 1


def test_distinct_sigma_rule_ids_are_not_deduplicated() -> None:
    first = _dns_sigma_rule("sigma-distinct-1")
    second = _dns_sigma_rule("sigma-distinct-2")

    converted = convert_sigma_to_wazuh([first, second])

    assert len(converted) == 2
    assert len({rule.rule_id for rule in converted}) == 2


def test_conflicting_sigma_rules_with_same_id_are_rejected() -> None:
    first = SigmaRule(
        title="First",
        rule_id="sigma-conflict",
        description="First",
        logsource={"category": "dns_query", "product": "windows"},
        detection={"selection": {"QueryName|contains": "first.example"}, "condition": "selection"},
    )
    second = SigmaRule(
        title="Second",
        rule_id="sigma-conflict",
        description="Second",
        logsource={"category": "dns_query", "product": "windows"},
        detection={"selection": {"QueryName|contains": "second.example"}, "condition": "selection"},
    )

    with pytest.raises(ValueError, match="Conflicting Sigma rules"):
        convert_sigma_to_wazuh([first, second])


def test_known_sigma_field_supports_a_different_safe_match_modifier() -> None:
    sigma_rule = SigmaRule(
        title="Image contains",
        rule_id="sigma-image-contains",
        description="Image path contains a marker",
        logsource={"category": "process_creation", "product": "windows"},
        detection={"selection": {"Image|contains": "suspicious"}, "condition": "selection"},
    )

    converted = convert_sigma_to_wazuh([sigma_rule])

    assert converted[0].fields == {"win.eventdata.image": "suspicious"}
    assert converted[0].field_match_types == {"win.eventdata.image": "contains"}


def test_empty_input_returns_empty_results_and_valid_group_xml() -> None:
    assert convert_sigma_to_wazuh([]) == []
    xml_text = wazuh_rules_to_xml([])
    root = ET.fromstring(xml_text)
    assert root.tag == "group"
    assert root.findall("./rule") == []


def test_linux_sigma_rules_do_not_use_sysmon_or_win_eventdata() -> None:
    sigma_rule = SigmaRule(
        title="Mozi Direct HTTP Download",
        rule_id="sigma-linux-mozi",
        description="HTTP connection observed: http://110.37.53.25:58088/i",
        logsource={"category": "network_connection", "product": "linux"},
        detection={
            "selection": {
                "destination.ip": "110.37.53.25",
                "url|contains": "http://110.37.53.25:58088/i",
            },
            "condition": "selection",
        },
        tags=["attack.t1071.001"],
        metadata={"platform_context": "linux_or_iot"},
    )

    rule = convert_sigma_to_wazuh([sigma_rule])[0]
    xml_text = wazuh_rule_to_xml(rule)

    assert rule.if_sid is None
    assert rule.group == "linux,network_connection,"
    assert "win.eventdata" not in xml_text
    assert "sysmon" not in xml_text.lower()
    assert r'<field name="dstip" type="pcre2">(?i)^110\.37\.53\.25$</field>' in xml_text
    assert "Linux/generic" in rule.options["trace"]["conversion_reason"]


def test_windows_non_process_rules_use_sysmon_parent_groups() -> None:
    sigma_rules = [
        SigmaRule(
            title="File Rule",
            rule_id="sigma-file-parent",
            description="File written",
            logsource={"category": "file_event", "product": "windows"},
            detection={"selection": {"TargetFilename|contains": "C:\\Temp\\drop.exe"}, "condition": "selection"},
        ),
        SigmaRule(
            title="Network Rule",
            rule_id="sigma-network-parent",
            description="Network connection",
            logsource={"category": "network_connection", "product": "windows"},
            detection={"selection": {"DestinationIp": "10.20.30.40"}, "condition": "selection"},
        ),
        SigmaRule(
            title="Registry Rule",
            rule_id="sigma-registry-parent",
            description="Registry value changed",
            logsource={"category": "registry_event", "product": "windows"},
            detection={"selection": {"TargetObject|contains": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}, "condition": "selection"},
        ),
        SigmaRule(
            title="DNS Rule",
            rule_id="sigma-dns-parent",
            description="DNS query",
            logsource={"category": "dns_query", "product": "windows"},
            detection={"selection": {"QueryName|contains": "example.test"}, "condition": "selection"},
        ),
    ]

    rules = convert_sigma_to_wazuh(sigma_rules)
    xml_text = wazuh_rules_to_xml(rules)

    assert [rule.if_group for rule in rules] == ["sysmon_event_11", "sysmon_event3", None, "sysmon_event_22"]
    assert rules[2].if_sid == "61614,61615,61616"
    assert "win.system.eventID" not in rules[2].fields
    assert "<if_sid>61614,61615,61616</if_sid>" in xml_text
    assert all(rule.decoded_as is None for rule in rules)
    assert "<decoded_as>json</decoded_as>" not in xml_text


def test_wazuh_regex_preserves_sigma_match_semantics() -> None:
    sigma_rule = SigmaRule(
        title="Semantics",
        rule_id="sigma-match-semantics",
        description="Match semantics",
        logsource={"category": "process_creation", "product": "windows"},
        detection={
            "selection": {
                "Image|endswith": "tool.exe",
                "CommandLine|contains": "--safe.mode",
            },
            "condition": "selection",
        },
    )

    xml_text = wazuh_rule_to_xml(convert_sigma_to_wazuh([sigma_rule])[0])

    assert '<field name="win.eventdata.image" type="pcre2">(?i)tool\\.exe$</field>' in xml_text
    assert '<field name="win.eventdata.commandLine" type="pcre2">(?i)--safe\\.mode</field>' in xml_text


def test_exact_image_path_is_not_reduced_to_a_basename() -> None:
    sigma_rule = SigmaRule(
        title="Exact image path",
        rule_id="sigma-exact-image-path",
        description="Exact system cmd path",
        logsource={"category": "process_creation", "product": "windows"},
        detection={"selection": {"Image": r"C:\Windows\System32\cmd.exe"}, "condition": "selection"},
    )

    converted = convert_sigma_to_wazuh([sigma_rule])[0]
    xml_text = wazuh_rule_to_xml(converted)

    assert converted.fields == {"win.eventdata.image": r"C:\Windows\System32\cmd.exe"}
    assert converted.field_match_types == {"win.eventdata.image": "exact"}
    assert r"(?i)^C:\\Windows\\System32\\cmd\.exe$" in xml_text


def test_command_line_only_rule_does_not_infer_an_image_constraint() -> None:
    command_line = r'"C:\Program Files\Tool\tool.exe" /x'
    sigma_rule = SigmaRule(
        title="Quoted command line",
        rule_id="sigma-quoted-command-line",
        description="Quoted executable path",
        logsource={"category": "process_creation", "product": "windows"},
        detection={"selection": {"CommandLine|contains": command_line}, "condition": "selection"},
    )

    converted = convert_sigma_to_wazuh([sigma_rule])[0]

    assert converted.fields == {"win.eventdata.commandLine": command_line}
    assert "win.eventdata.image" not in wazuh_rule_to_xml(converted)


def test_shared_registry_prevents_ids_colliding_across_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wazuh_converter, "_deterministic_wazuh_id", lambda _: 100000)
    registry: dict[str, int] = {}
    ids: list[int] = []
    for index in range(3):
        sigma_rule = SigmaRule(
            title=f"Rule {index}",
            rule_id=f"sigma-registry-{index}",
            description=f"Rule {index}",
            logsource={"category": "dns_query", "product": "windows"},
            detection={"selection": {"QueryName|contains": f"host{index}.example"}, "condition": "selection"},
        )
        ids.append(
            convert_sigma_to_wazuh(
                [sigma_rule],
                id_registry=registry,
                id_namespace=f"report-{index}",
            )[0].rule_id
        )

    assert ids == [100000, 100001, 100002]
    assert len(set(registry.values())) == 3


def test_or_condition_creates_one_wazuh_rule_per_selector() -> None:
    sigma_rule = SigmaRule(
        title="Either Domain",
        rule_id="sigma-or-domains",
        description="Either domain queried",
        logsource={"category": "dns_query", "product": "windows"},
        detection={
            "selection_a": {"QueryName|contains": "a.example"},
            "selection_b": {"QueryName|contains": "b.example"},
            "condition": "1 of selection_*",
        },
    )

    converted = convert_sigma_to_wazuh([sigma_rule])

    assert len(converted) == 2
    assert len({rule.rule_id for rule in converted}) == 2
    assert {rule.fields["win.eventdata.queryName"] for rule in converted} == {"a.example", "b.example"}
    assert all(len(rule.options["trace"]["source_sigma_selectors"]) == 1 for rule in converted)


@pytest.mark.parametrize(
    "invalid_range",
    [
        range(100000, 100000),
        range(0, 2),
        range(100000, 100005, 2),
    ],
    ids=["empty", "nonpositive", "non-unit-step"],
)
def test_invalid_explicit_wazuh_id_ranges_are_rejected(invalid_range: range) -> None:
    with pytest.raises(ValueError):
        convert_sigma_to_wazuh([_dns_sigma_rule()], id_range=invalid_range)


@pytest.mark.parametrize(
    "invalid_registry",
    [
        {1: 100000},
        {"": 100000},
        {"rule": True},
        {"rule": "100000"},
        {"rule": 99999},
        {"first": 100000, "second": 100000},
    ],
    ids=["non-string-key", "blank-key", "boolean", "non-integer", "out-of-range", "duplicate"],
)
def test_invalid_wazuh_id_registries_are_rejected(invalid_registry: dict[object, object]) -> None:
    with pytest.raises(ValueError):
        convert_sigma_to_wazuh(
            [_dns_sigma_rule()],
            id_registry=invalid_registry,  # type: ignore[arg-type]
            id_range=range(100000, 100002),
        )


def test_sigma_list_selector_values_fail_loudly() -> None:
    sigma_rule = _dns_sigma_rule()
    sigma_rule.detection["selection"] = {"QueryName|contains": ["a.example", "b.example"]}

    with pytest.raises(ValueError, match="list selector values"):
        convert_sigma_to_wazuh([sigma_rule])


@pytest.mark.parametrize(
    "sigma_field",
    ["CommandLine|contains|all", "CommandLine|contains|cased"],
    ids=["all", "cased"],
)
def test_unsupported_sigma_field_modifiers_fail_loudly(sigma_field: str) -> None:
    sigma_rule = SigmaRule(
        title="Multiple Required Arguments",
        rule_id="sigma-unsupported-all",
        description="Command contains all required arguments",
        logsource={"category": "process_creation", "product": "windows"},
        detection={
            "selection": {sigma_field: "--required"},
            "condition": "selection",
        },
    )

    with pytest.raises(ValueError, match="Unsupported Sigma field modifier"):
        convert_sigma_to_wazuh([sigma_rule])
