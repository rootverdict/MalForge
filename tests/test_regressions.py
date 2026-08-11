"""Regression tests for defects found during the V1 completion audit."""

from __future__ import annotations

import pytest

from converters.wazuh_converter import convert_sigma_to_wazuh, wazuh_rules_to_xml
from core.models import Behavior, IOC, SigmaRule
from core.sigma_syntax import unescape_sigma_value
from enrichment.urlhaus import load_urlhaus_indicators
from extractor.file_extractor import extract_behaviors as extract_file_behaviors
from extractor.registry_extractor import extract_behaviors as extract_registry_behaviors
from generators.sigma_generator import generate_sigma_rules
from quality.test_event_generator import generate_test_events
from reporting.report_generator import generate_markdown_report
from reporting.summary import build_summary


def _sigma_selector_values(rule: SigmaRule) -> dict[str, str]:
    values: dict[str, str] = {}
    for name, selector in rule.detection.items():
        if name.startswith("selection") and isinstance(selector, dict):
            values.update({str(key): str(value) for key, value in selector.items()})
    return values


# --- Markdown report section structure ---------------------------------------


def test_source_data_limitations_does_not_swallow_the_behavior_summary() -> None:
    summary = build_summary(
        normalized_report={"sandbox": "cuckoo", "sample": {"name": "x.exe", "hashes": {}}},
        behaviors=[Behavior(category="file", description="File written: /tmp/x", source="cuckoo")],
        generated_at="2026-06-28T10:00:00+00:00",
    )

    report = generate_markdown_report(summary=summary)
    lines = report.splitlines()
    limitations_index = lines.index("## Source Data Limitations")
    behavior_index = lines.index("## Behavior Summary")

    assert limitations_index < behavior_index
    # The behavior counts must sit under Behavior Summary, not under Limitations.
    assert "- file: 1" in lines[behavior_index:]
    assert "- file: 1" not in lines[limitations_index:behavior_index]


def test_summary_generates_its_own_timestamp_when_none_is_supplied() -> None:
    summary = build_summary(normalized_report={"sandbox": "cuckoo", "sample": {}})

    assert summary["generated_at"].endswith("+00:00")


# --- Sigma escaping -----------------------------------------------------------


def test_command_line_wildcards_are_escaped_so_the_rule_still_matches() -> None:
    behavior = Behavior(
        category="process",
        description="Process created: x.exe",
        source="cuckoo",
        evidence=[{"process_name": "x.exe", "command_line": r"x.exe /c dir C:\Temp\*.dll"}],
    )

    rule = generate_sigma_rules([behavior])[0]
    value = _sigma_selector_values(rule)["CommandLine|contains"]

    assert value == r"x.exe /c dir C:\\Temp\\\*.dll"
    assert unescape_sigma_value(value) == r"x.exe /c dir C:\Temp\*.dll"


def test_url_query_marker_is_escaped_instead_of_acting_as_a_wildcard() -> None:
    behavior = Behavior(
        category="network",
        description="HTTP connection observed: http://evil.test/a.php?id=1",
        source="cuckoo",
        evidence=[{"url": "http://evil.test/a.php?id=1"}],
        tags=["platform_non_windows"],
    )

    rule = generate_sigma_rules([behavior])[0]
    value = _sigma_selector_values(rule)["url|contains"]

    assert r"\?" in value
    assert unescape_sigma_value(value) == "http://evil.test/a.php?id=1"


def test_windows_paths_never_emit_a_trailing_lone_backslash() -> None:
    behavior = Behavior(
        category="file",
        description="File written: C:\\Users\\bob\\",
        source="cuckoo",
        evidence=[{"path": "C:\\Users\\bob\\"}],
    )

    rule = generate_sigma_rules([behavior])[0]
    value = _sigma_selector_values(rule)["TargetFilename|contains"]

    trailing = len(value) - len(value.rstrip("\\"))
    assert trailing % 2 == 0, "a lone trailing backslash is rejected by Sigma parsers"


def test_registry_selector_escapes_backslashes() -> None:
    behavior = Behavior(
        category="registry",
        description="Registry key modified: HKCU\\Software\\X",
        source="cuckoo",
        evidence=[{"key": "HKCU\\Software\\X"}],
    )

    rule = generate_sigma_rules([behavior])[0]
    value = _sigma_selector_values(rule)["TargetObject|contains"]

    assert value == "HKCU\\\\Software\\\\X"


# --- Sigma fields list --------------------------------------------------------


@pytest.mark.parametrize(
    ("behavior", "expected_fields"),
    [
        (
            Behavior(
                category="network",
                description="DNS lookup observed: api.example.test",
                source="cuckoo",
                evidence=[{"domain": "api.example.test"}],
            ),
            ["QueryName"],
        ),
        (
            Behavior(
                category="network",
                description="HTTP connection observed: http://evil.test/a",
                source="cuckoo",
                evidence=[{"url": "http://evil.test/a"}],
                tags=["platform_non_windows"],
            ),
            ["url", "destination.domain"],
        ),
    ],
)
def test_fields_list_holds_plain_log_field_names(behavior: Behavior, expected_fields: list[str]) -> None:
    rule = generate_sigma_rules([behavior])[0]

    assert rule.fields == expected_fields
    assert all("|" not in field for field in rule.fields)


# --- Wazuh conversion ---------------------------------------------------------


def test_wazuh_conversion_unescapes_sigma_values_without_double_escaping() -> None:
    behavior = Behavior(
        category="file",
        description="File written: C:\\Users\\bob\\report.txt",
        source="cuckoo",
        evidence=[{"path": "C:\\Users\\bob\\report.txt"}],
    )

    wazuh_rule = convert_sigma_to_wazuh(generate_sigma_rules([behavior]))[0]

    assert wazuh_rule.fields["win.eventdata.targetFilename"] == "C:\\Users\\bob\\report.txt"
    assert "\\\\\\\\" not in wazuh_rules_to_xml([wazuh_rule])


def test_unmapped_sigma_field_is_rejected_rather_than_silently_dropped() -> None:
    rule = SigmaRule(
        title="Custom",
        rule_id="11111111-1111-5111-8111-111111111111",
        description="Custom rule",
        logsource={"category": "process_creation", "product": "windows"},
        detection={
            "selection": {"Image|endswith": "x.exe", "ParentImage|endswith": "explorer.exe"},
            "condition": "selection",
        },
    )

    with pytest.raises(ValueError, match="no Wazuh equivalent"):
        convert_sigma_to_wazuh([rule])


def test_process_creation_xml_keeps_parent_rule_and_field_order() -> None:
    behavior = Behavior(
        category="process",
        description="Process created: x.exe",
        source="cuckoo",
        evidence=[{"process_name": "x.exe", "command_line": "x.exe -run"}],
    )

    xml = wazuh_rules_to_xml(convert_sigma_to_wazuh(generate_sigma_rules([behavior])))

    assert "<if_sid>61603</if_sid>" in xml
    assert xml.index("<if_sid>") < xml.index("<field") < xml.index("<description>")


# --- Synthetic test events ----------------------------------------------------


def test_positive_events_carry_literal_values_not_escaped_ones() -> None:
    behavior = Behavior(
        category="file",
        description="File written: C:\\Users\\bob\\x.txt",
        source="cuckoo",
        evidence=[{"path": "C:\\Users\\bob\\x.txt"}],
    )

    events = generate_test_events(generate_sigma_rules([behavior])[0])

    assert events["positive"][0]["TargetFilename"] == "C:\\Users\\bob\\x.txt"


def test_negative_event_never_reuses_the_observed_value() -> None:
    behavior = Behavior(
        category="process",
        description="Process created: notepad.exe",
        source="cuckoo",
        evidence=[{"process_name": "notepad.exe"}],
    )

    events = generate_test_events(generate_sigma_rules([behavior])[0])
    negative = str(events["negative"][0]["Image"])

    assert "notepad.exe" not in negative.lower()


def test_negative_event_values_are_stable_across_runs() -> None:
    behavior = Behavior(
        category="process",
        description="Process created: notepad.exe",
        source="cuckoo",
        evidence=[{"process_name": "notepad.exe"}],
    )
    rule = generate_sigma_rules([behavior])[0]

    assert generate_test_events(rule) == generate_test_events(rule)


# --- Extractor precision ------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "is_drop"),
    [
        ("C:\\Windows\\System32\\template.dll", False),
        ("C:\\Users\\Public\\Documents\\publication.pdf", True),
        ("C:\\Temp\\stage.bin", True),
        ("C:\\Users\\bob\\AppData\\Roaming\\x.exe", True),
        ("C:\\Program Files\\App\\tmplugin.dll", False),
    ],
)
def test_drop_path_detection_matches_whole_segments_only(path: str, is_drop: bool) -> None:
    behaviors = extract_file_behaviors({"sandbox": "cuckoo", "files": [path]})

    assert ("file_drop" in behaviors[0].tags) is is_drop


@pytest.mark.parametrize(
    ("key", "is_run_key"),
    [
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", True),
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", True),
        ("HKLM\\Software\\Vendor\\Runtime", False),
        ("HKLM\\System\\CurrentControlSet\\Services\\Running", False),
    ],
)
def test_run_key_detection_matches_whole_key_segments_only(key: str, is_run_key: bool) -> None:
    behaviors = extract_registry_behaviors({"sandbox": "cuckoo", "registry": [key]})

    assert ("registry_run_key" in behaviors[0].tags) is is_run_key


# --- Offline URLhaus ----------------------------------------------------------


def test_urlhaus_loader_skips_rows_without_a_url_column(tmp_path) -> None:
    csv_path = tmp_path / "urlhaus.csv"
    csv_path.write_text(
        "# comment\n"
        "1,2026-01-01 00:00:00,http://evil.test/a,online\n"
        "2,2026-01-02 00:00:00\n",
        encoding="utf-8",
    )

    urls, domains = load_urlhaus_indicators(csv_path)

    assert urls == {"http://evil.test/a"}
    assert domains == {"evil.test"}
    assert not any(value.startswith("2026-") for value in urls)


def test_urlhaus_enrichment_makes_no_network_call(tmp_path) -> None:
    from enrichment.urlhaus import enrich_iocs_with_urlhaus

    csv_path = tmp_path / "urlhaus.csv"
    csv_path.write_text("1,2026-01-01 00:00:00,http://evil.test/a,online\n", encoding="utf-8")
    iocs = [IOC(type="url", value="http://evil.test/a", source="cuckoo")]

    result = enrich_iocs_with_urlhaus(iocs, csv_path)

    assert result["network_call_performed"] is False
    assert result["match_count"] == 1
    assert iocs[0].confidence == 0.9


# --- Validator now catches the defect classes this audit fixed ----------------


def _sigma_rule(**overrides) -> SigmaRule:
    payload = {
        "title": "T",
        "rule_id": "11111111-1111-5111-8111-111111111111",
        "description": "d",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"selection": {"CommandLine|contains": "a"}, "condition": "selection"},
        "tags": ["attack.t1059"],
        "falsepositives": ["Unknown"],
        "fields": ["CommandLine"],
    }
    payload.update(overrides)
    return SigmaRule(**payload)


def test_validator_rejects_modifiers_in_the_fields_list() -> None:
    from quality.validator import validate_sigma_rule

    result = validate_sigma_rule(_sigma_rule(fields=["QueryName|contains"]))

    assert result.is_valid is False
    assert any("plain log field names" in error for error in result.errors)


def test_validator_rejects_a_trailing_lone_backslash() -> None:
    from quality.validator import validate_sigma_rule

    result = validate_sigma_rule(
        _sigma_rule(
            detection={
                "selection": {"TargetFilename|contains": r"C:\Users\bob" + "\\"},
                "condition": "selection",
            }
        )
    )

    assert result.is_valid is False
    assert any("lone backslash" in error for error in result.errors)


def test_validator_warns_about_raw_unescaped_windows_paths() -> None:
    from quality.validator import validate_sigma_rule

    result = validate_sigma_rule(
        _sigma_rule(
            detection={
                "selection": {"CommandLine|contains": r"dir C:\Temp\*.dll"},
                "condition": "selection",
            }
        )
    )

    assert any("raw backslashes" in warning for warning in result.warnings)


def test_validator_warns_about_unescaped_wildcards() -> None:
    from quality.validator import validate_sigma_rule

    result = validate_sigma_rule(
        _sigma_rule(detection={"selection": {"CommandLine|contains": "svc*.exe"}, "condition": "selection"})
    )

    assert any("unescaped wildcard" in warning for warning in result.warnings)


def test_validator_stays_quiet_on_correctly_escaped_generated_rules() -> None:
    from quality.validator import validate_sigma_rule

    behavior = Behavior(
        category="process",
        description="Process created: svc.exe",
        source="cuckoo",
        evidence=[{"process_name": "svc.exe", "command_line": r"svc.exe /c dir C:\Temp\*.dll"}],
        technique_ids=["T1059"],
    )
    rule = generate_sigma_rules([behavior])[0]

    result = validate_sigma_rule(rule)

    assert result.is_valid is True
    assert not [w for w in result.warnings if "backslash" in w or "wildcard" in w]
