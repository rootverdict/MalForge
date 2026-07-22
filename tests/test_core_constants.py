"""Tests for shared project constants."""

from core.constants import (
    ATTACK_VERSION,
    ATTACK_TACTIC_IDS,
    COMMON_ATTACK_MAPPINGS,
    OUTPUT_PATHS,
    PROJECT_ROOT,
    SIGMA_TO_WAZUH_LEVEL,
    WAZUH_CUSTOM_RULE_ID_RANGE,
    WAZUH_RULE_ID_END,
    WAZUH_RULE_ID_START,
)


def test_output_paths_are_under_project_output_directory() -> None:
    assert OUTPUT_PATHS["sigma"].is_relative_to(PROJECT_ROOT / "output")
    assert OUTPUT_PATHS["navigator"].name == "navigator"


def test_sigma_to_wazuh_mapping_covers_expected_levels() -> None:
    assert SIGMA_TO_WAZUH_LEVEL["critical"] == 14
    assert SIGMA_TO_WAZUH_LEVEL["informational"] < SIGMA_TO_WAZUH_LEVEL["high"]


def test_common_attack_mappings_cover_requested_behavior_groups() -> None:
    assert COMMON_ATTACK_MAPPINGS["process"]["powershell"]["technique_id"] == "T1059.001"
    assert COMMON_ATTACK_MAPPINGS["registry"]["run_key"]["tactic"] == "persistence"
    assert COMMON_ATTACK_MAPPINGS["file"]["masquerading"]["technique_name"] == "Masquerading"
    assert COMMON_ATTACK_MAPPINGS["network"]["dns_query"]["technique_id"] == "T1071.004"
    assert "ip_connection" not in COMMON_ATTACK_MAPPINGS["network"]
    assert COMMON_ATTACK_MAPPINGS["network"]["non_standard_port"]["technique_id"] == "T1571"
    assert COMMON_ATTACK_MAPPINGS["persistence"]["service_install"]["technique_id"] == "T1543.003"
    assert ATTACK_TACTIC_IDS["execution"] == "TA0002"
    assert ATTACK_TACTIC_IDS["initial_access"] == "TA0001"
    assert ATTACK_TACTIC_IDS["stealth"] == "TA0005"
    assert ATTACK_TACTIC_IDS["defense_impairment"] == "TA0112"
    assert "defense_evasion" not in ATTACK_TACTIC_IDS
    assert len(ATTACK_TACTIC_IDS) == 15


def test_wazuh_rule_range_matches_exposed_bounds() -> None:
    assert WAZUH_RULE_ID_START == 100000
    assert WAZUH_RULE_ID_END == 119999
    assert 100500 in WAZUH_CUSTOM_RULE_ID_RANGE


def test_attack_metadata_tracks_current_release() -> None:
    assert ATTACK_VERSION == "19.1"


def test_attack_v19_mappings_use_current_split_tactics() -> None:
    assert COMMON_ATTACK_MAPPINGS["process"]["process_injection"]["tactic"] == "stealth"
    assert COMMON_ATTACK_MAPPINGS["process"]["rundll32"]["tactic"] == "stealth"
    assert COMMON_ATTACK_MAPPINGS["registry"]["registry_modification"]["tactic"] == "defense_impairment"
    assert COMMON_ATTACK_MAPPINGS["file"]["file_delete"]["tactic"] == "stealth"
