"""Tests for reporting summary and Markdown generation."""

from __future__ import annotations

import json
from pathlib import Path

from attck.mapper import map_behaviors_to_attack
from attck.navigator import generate_navigator_layer
from converters.wazuh_converter import convert_sigma_to_wazuh
from core.schema import load_json_report
from extractor import extract_behaviors
from generators.sigma_generator import generate_sigma_rules
from ioc.ioc_extractor import extract_all_iocs
from ingestion.anyrun import parse_report as parse_anyrun_report
from ingestion.cape import parse_report as parse_cape_report
from ingestion.cuckoo import parse_report as parse_cuckoo_report
from quality.risk_scorer import score_rule
from quality.validator import validate_sigma_rules, validate_wazuh_rules
from reporting.report_generator import generate_markdown_report
from reporting.summary import build_summary
from review.reviewer import create_review_record

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _fixture_artifacts() -> dict[str, object]:
    normalized_report = parse_anyrun_report(load_json_report(FIXTURES_DIR / "sample_anyrun_report.json"))
    behaviors = extract_behaviors(normalized_report)
    iocs = extract_all_iocs(normalized_report, behaviors)
    mappings = map_behaviors_to_attack(behaviors)
    sigma_rules = generate_sigma_rules(behaviors, mappings)
    wazuh_rules = convert_sigma_to_wazuh(sigma_rules)
    validation_results = validate_sigma_rules(sigma_rules) + validate_wazuh_rules(wazuh_rules)
    risk_scores = [score_rule(rule) for rule in sigma_rules[:1] + wazuh_rules[:1]]
    review_records = [create_review_record("approved", reviewer="analyst", notes="Ready for export.")]
    navigator_layer = generate_navigator_layer(mappings, name="Fixture Layer")
    return {
        "normalized_report": normalized_report,
        "behaviors": behaviors,
        "iocs": iocs,
        "attack_mappings": mappings,
        "sigma_rules": sigma_rules,
        "wazuh_rules": wazuh_rules,
        "validation_results": validation_results,
        "risk_scores": risk_scores,
        "review_records": review_records,
        "navigator_layer": navigator_layer,
    }


def test_summary_is_json_serializable() -> None:
    summary = build_summary(**_fixture_artifacts(), generated_at="2026-06-28T10:00:00+00:00")

    payload = json.dumps(summary)

    assert isinstance(payload, str)


def test_counts_are_correct_for_sample_artifacts() -> None:
    summary = build_summary(**_fixture_artifacts(), generated_at="2026-06-28T10:00:00+00:00")

    assert summary["sample"]["sandbox"] == "anyrun"
    assert summary["counts"]["behaviors_by_category"]["process"] >= 1
    assert summary["counts"]["iocs_by_type"]["domain"] >= 1
    assert summary["counts"]["attack_technique_count"] >= 1
    assert summary["counts"]["sigma_rule_count"] >= 1
    assert summary["counts"]["wazuh_rule_count"] >= 1


def test_markdown_report_contains_expected_headings() -> None:
    report = generate_markdown_report(
        **_fixture_artifacts(),
        generated_at="2026-06-28T10:00:00+00:00",
    )

    assert "# Malware Behavior Detection Report" in report
    assert "## Sample Overview" in report
    assert "## Behavior Summary" in report
    assert "## IOC Summary" in report
    assert "## ATT&CK Mappings" in report
    assert "## Generated Sigma Rules" in report
    assert "## Generated Wazuh Rules" in report
    assert "### IOC Values" in report


def test_empty_input_produces_useful_report() -> None:
    summary = build_summary(generated_at="2026-06-28T10:00:00+00:00")
    report = generate_markdown_report(summary=summary)

    assert summary["counts"]["sigma_rule_count"] == 0
    assert "No behaviors extracted." in report
    assert "No Sigma rules generated." in report


def test_validation_risk_and_review_sections_appear_when_provided() -> None:
    report = generate_markdown_report(
        **_fixture_artifacts(),
        generated_at="2026-06-28T10:00:00+00:00",
    )

    assert "## Validation Warnings" in report
    assert "## Risk Scoring" in report
    assert "## Review Status" in report


def test_generated_at_can_be_caller_provided_for_deterministic_tests() -> None:
    timestamp = "2026-06-28T10:00:00+00:00"
    summary = build_summary(**_fixture_artifacts(), generated_at=timestamp)

    assert summary["generated_at"] == timestamp


def test_summary_and_report_include_rule_traceability() -> None:
    artifacts = _fixture_artifacts()
    summary = build_summary(**artifacts, generated_at="2026-06-28T10:00:00+00:00")
    report = generate_markdown_report(summary=summary)

    assert summary["artifacts"]["sigma_rule_traces"]
    assert summary["artifacts"]["wazuh_rule_traces"]
    assert "## Rule Generation Rationale" in report


def test_missing_hashes_are_called_out_in_summary_and_report() -> None:
    normalized_report = {
        "sandbox": "cuckoo",
        "sample": {"name": "mozi.m", "hashes": {"md5": "", "sha1": None, "sha256": ""}},
    }

    summary = build_summary(normalized_report=normalized_report, generated_at="2026-06-28T10:00:00+00:00")
    report = generate_markdown_report(summary=summary)

    assert summary["sample"]["hash_status"]["complete"] is False
    assert summary["sample"]["hash_status"]["missing"] == ["md5", "sha1", "sha256"]
    assert "## Source Data Limitations" in report
    assert "Missing payload hashes: md5, sha1, sha256" in report