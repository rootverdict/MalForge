"""Tests for review metadata and deterministic rule versioning."""

from __future__ import annotations

from pathlib import Path

import pytest

from attck.mapper import map_behaviors_to_attack
from converters.wazuh_converter import convert_sigma_to_wazuh
from core.models import SigmaRule, WazuhRule
from core.schema import load_json_report
from extractor import extract_behaviors
from generators.sigma_generator import generate_sigma_rules
from ingestion.anyrun import parse_report as parse_anyrun_report
from ingestion.cape import parse_report as parse_cape_report
from ingestion.cuckoo import parse_report as parse_cuckoo_report
from review.reviewer import (
    apply_review_to_rule,
    apply_review_to_rules,
    create_review_record,
)
from review.versioner import version_rule, version_rules

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _fixture_rules() -> tuple[SigmaRule, WazuhRule]:
    reports = [
        parse_cuckoo_report(load_json_report(FIXTURES_DIR / "sample_cuckoo_report.json")),
        parse_cape_report(load_json_report(FIXTURES_DIR / "sample_cape_report.json")),
        parse_anyrun_report(load_json_report(FIXTURES_DIR / "sample_anyrun_report.json")),
    ]
    behaviors = []
    for report in reports:
        behaviors.extend(extract_behaviors(report))
    mappings = map_behaviors_to_attack(behaviors)
    sigma_rule = generate_sigma_rules(behaviors, mappings)[0]
    wazuh_rule = convert_sigma_to_wazuh([sigma_rule])[0]
    return sigma_rule, wazuh_rule


def test_valid_review_states_are_accepted() -> None:
    review = create_review_record("approved", reviewer="analyst", notes="Looks good.")

    assert review["status"] == "approved"
    assert review["reviewer"] == "analyst"


def test_invalid_review_states_raise() -> None:
    with pytest.raises(ValueError):
        create_review_record("pending_human")


def test_review_metadata_can_be_applied_to_sigma_and_wazuh_rules() -> None:
    sigma_rule, wazuh_rule = _fixture_rules()
    review = create_review_record("needs_tuning", reviewer="alice", notes="Tighten selector.")

    reviewed_sigma = apply_review_to_rule(sigma_rule, review)
    reviewed_wazuh = apply_review_to_rule(wazuh_rule, review)

    assert reviewed_sigma.metadata["review"]["status"] == "needs_tuning"
    assert reviewed_wazuh.options["review"]["reviewer"] == "alice"
    assert "review" not in sigma_rule.metadata


def test_version_metadata_contains_expected_keys() -> None:
    sigma_rule, wazuh_rule = _fixture_rules()
    timestamp = "2026-06-28T10:00:00+00:00"

    versioned_sigma = version_rule(
        sigma_rule,
        rule_version="2.1.0",
        timestamp=timestamp,
        source_report_hash="abc123",
    )
    versioned_wazuh = version_rule(
        wazuh_rule,
        rule_version="2.1.0",
        timestamp=timestamp,
        source_report_hash="abc123",
    )

    sigma_version = versioned_sigma.metadata["version"]
    wazuh_version = versioned_wazuh.options["version"]

    for payload in (sigma_version, wazuh_version):
        assert payload["tool_name"] == "malware-behavior-detection-generator"
        assert payload["tool_version"] == "0.1.0"
        assert payload["rule_version"] == "2.1.0"
        assert payload["generated_at"] == timestamp
        assert payload["source_report_hash"] == "abc123"
        assert "content_hash" in payload


def test_content_hash_is_stable_for_same_rule_content() -> None:
    sigma_rule, wazuh_rule = _fixture_rules()
    timestamp = "2026-06-28T10:00:00+00:00"

    sigma_a = version_rule(sigma_rule, timestamp=timestamp)
    sigma_b = version_rule(sigma_rule, timestamp=timestamp)
    wazuh_a = version_rule(wazuh_rule, timestamp=timestamp)
    wazuh_b = version_rule(wazuh_rule, timestamp=timestamp)

    assert sigma_a.metadata["version"]["content_hash"] == sigma_b.metadata["version"]["content_hash"]
    assert wazuh_a.options["version"]["content_hash"] == wazuh_b.options["version"]["content_hash"]


def test_caller_provided_timestamp_makes_output_deterministic() -> None:
    sigma_rule, _ = _fixture_rules()
    timestamp = "2026-06-28T10:00:00+00:00"

    first = version_rule(sigma_rule, timestamp=timestamp)
    second = version_rule(sigma_rule, timestamp=timestamp)

    assert first.metadata["version"]["generated_at"] == timestamp
    assert first.metadata["version"] == second.metadata["version"]


def test_empty_inputs_are_handled_gracefully() -> None:
    review = create_review_record("unreviewed")
    assert apply_review_to_rules([], review) == []
    assert version_rules([], timestamp="2026-06-28T10:00:00+00:00") == []
