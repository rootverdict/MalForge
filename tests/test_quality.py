"""Tests for validation, risk scoring, and synthetic test events."""

from __future__ import annotations

from pathlib import Path

from attck.mapper import map_behaviors_to_attack
from converters.wazuh_converter import convert_sigma_to_wazuh
from core.models import RiskScore, SigmaRule, WazuhRule
from core.pipeline import _derive_summary_risk
from core.schema import load_json_report
from extractor import extract_behaviors
from generators.sigma_generator import generate_sigma_rules
from ingestion.anyrun import parse_report as parse_anyrun_report
from ingestion.cape import parse_report as parse_cape_report
from ingestion.cuckoo import parse_report as parse_cuckoo_report
from quality.risk_scorer import score_rule
from quality.test_event_generator import generate_test_events
from quality.validator import (
    validate_sigma_rule,
    validate_sigma_rules,
    validate_wazuh_rule,
    validate_wazuh_rules,
)
import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _rs(score: float, severity: str = "medium") -> RiskScore:
    return RiskScore(score=score, severity=severity, rationale=[], factors={})


def _fixture_rules() -> tuple[list[SigmaRule], list[WazuhRule]]:
    reports = [
        parse_cuckoo_report(load_json_report(FIXTURES_DIR / "sample_cuckoo_report.json")),
        parse_cape_report(load_json_report(FIXTURES_DIR / "sample_cape_report.json")),
        parse_anyrun_report(load_json_report(FIXTURES_DIR / "sample_anyrun_report.json")),
    ]
    behaviors = []
    for report in reports:
        behaviors.extend(extract_behaviors(report))
    mappings = map_behaviors_to_attack(behaviors)
    sigma_rules = generate_sigma_rules(behaviors, mappings)
    wazuh_rules = convert_sigma_to_wazuh(sigma_rules)
    return sigma_rules, wazuh_rules


def test_valid_sigma_and_wazuh_rules_pass_validation() -> None:
    sigma_rules, wazuh_rules = _fixture_rules()

    sigma_result = validate_sigma_rule(sigma_rules[0])
    wazuh_result = validate_wazuh_rule(wazuh_rules[0])

    assert sigma_result.is_valid is True
    assert wazuh_result.is_valid is True


def test_malformed_rules_fail_validation() -> None:
    bad_sigma = SigmaRule(
        title="",
        rule_id="sigma-bad",
        description="",
        logsource={},
        detection={},
        level="low",
        falsepositives=[],
    )
    bad_wazuh = WazuhRule(rule_id=0, level=0, description="", decoded_as="", fields={})

    sigma_result = validate_sigma_rule(bad_sigma)
    wazuh_result = validate_wazuh_rule(bad_wazuh)

    assert sigma_result.is_valid is False
    assert wazuh_result.is_valid is False
    assert sigma_result.errors
    assert wazuh_result.errors


def test_warnings_are_produced_for_broad_or_noisy_rules() -> None:
    noisy_sigma = SigmaRule(
        title="Generic PowerShell",
        rule_id="sigma-noisy",
        description="Process created: powershell.exe",
        logsource={"category": "process_creation", "product": "windows"},
        detection={"selection": {"Image|endswith": "powershell.exe"}, "condition": "selection"},
        level="low",
        falsepositives=[],
        tags=[],
    )

    result = validate_sigma_rule(noisy_sigma)

    assert result.warnings
    assert any("broad" in warning.lower() or "missing" in warning.lower() for warning in result.warnings)


def test_risk_scores_are_bounded_and_deterministic() -> None:
    sigma_rules, wazuh_rules = _fixture_rules()

    sigma_score_a = score_rule(sigma_rules[0])
    sigma_score_b = score_rule(sigma_rules[0])
    wazuh_score = score_rule(wazuh_rules[0])

    assert 0.0 <= sigma_score_a.score <= 100.0
    assert 0.0 <= wazuh_score.score <= 100.0
    assert sigma_score_a.score == sigma_score_b.score


def test_test_events_include_positive_and_negative_cases() -> None:
    sigma_rules, wazuh_rules = _fixture_rules()

    sigma_events = generate_test_events(sigma_rules[0])
    wazuh_events = generate_test_events(wazuh_rules[0])

    assert "positive" in sigma_events and "negative" in sigma_events
    assert "positive" in wazuh_events and "negative" in wazuh_events
    assert sigma_events["positive"] and sigma_events["negative"]
    assert wazuh_events["positive"] and wazuh_events["negative"]


def test_generated_events_are_safe_dictionaries() -> None:
    sigma_rules, wazuh_rules = _fixture_rules()

    for bundle in (generate_test_events(sigma_rules[0]), generate_test_events(wazuh_rules[0])):
        for event in bundle["positive"] + bundle["negative"]:
            assert isinstance(event, dict)
            assert all(not callable(value) for value in event.values())


def test_empty_inputs_are_handled_gracefully() -> None:
    assert validate_sigma_rules([]) == []
    assert validate_wazuh_rules([]) == []


def test_derive_risk_empty_returns_none() -> None:
    assert _derive_summary_risk([]) is None


def test_derive_risk_single_rule() -> None:
    result = _derive_summary_risk([_rs(75.0, "high")])

    assert result is not None
    assert result.score == 75.0
    assert result.severity == "high"


def test_derive_risk_two_rules() -> None:
    result = _derive_summary_risk([_rs(30.0, "low"), _rs(80.0, "high")])

    assert result is not None
    assert result.score == 80.0
    assert result.severity == "high"


def test_derive_risk_all_identical() -> None:
    scores = [_rs(50.0, "medium") for _ in range(10)]
    result = _derive_summary_risk(scores)

    assert result is not None
    assert result.score == 50.0
    assert result.severity == "medium"


def test_derive_risk_critical_outlier_surfaces_as_high() -> None:
    scores = [_rs(50.0, "medium") for _ in range(9)]
    scores.append(_rs(92.0, "critical"))
    result = _derive_summary_risk(scores)

    assert result is not None
    assert result.score == 71.0
    assert result.severity == "high"


def test_derive_risk_all_critical() -> None:
    scores = [_rs(90.0, "critical") for _ in range(5)]
    result = _derive_summary_risk(scores)

    assert result is not None
    assert result.score == 90.0
    assert result.severity == "critical"


def test_derive_risk_all_low() -> None:
    scores = [_rs(25.0, "low") for _ in range(4)]
    result = _derive_summary_risk(scores)

    assert result is not None
    assert result.score == 25.0
    assert result.severity == "low"


def test_risk_score_model_rejects_above_100() -> None:
    with pytest.raises(ValueError):
        RiskScore(score=150.0, severity="critical")


def test_risk_score_model_rejects_negative() -> None:
    with pytest.raises(ValueError):
        RiskScore(score=-1.0, severity="low")


def test_derive_risk_rationale_and_factors_populated() -> None:
    scores = [_rs(60.0, "medium"), _rs(80.0, "high")]
    result = _derive_summary_risk(scores)

    assert result is not None
    assert isinstance(result.rationale, list)
    assert len(result.rationale) == 3
    assert "rule_count" in result.factors
    assert result.factors["rule_count"] == 2
    assert "p90_score" in result.factors
    assert "top_avg" in result.factors
