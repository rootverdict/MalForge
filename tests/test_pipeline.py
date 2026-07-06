"""Tests for end-to-end pipeline orchestration and CLI."""

from __future__ import annotations

import json
from pathlib import Path

from core.pipeline import run_pipeline
from main import main

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_pipeline_runs_end_to_end_without_writing() -> None:
    report_path = FIXTURES_DIR / "sample_cuckoo_report.json"

    result = run_pipeline(report_path, write_output=False)

    assert result.behaviors
    assert result.iocs
    assert result.attack_mappings
    assert result.sigma_rules
    assert result.wazuh_rules
    assert result.metadata["output_files"] == {}
    sigma_timestamps = {rule.metadata["version"]["generated_at"] for rule in result.sigma_rules}
    wazuh_timestamps = {rule.options["version"]["generated_at"] for rule in result.wazuh_rules}
    assert len(sigma_timestamps) == 1
    assert len(wazuh_timestamps) == 1


def test_pipeline_writes_expected_files(tmp_path: Path) -> None:
    report_path = FIXTURES_DIR / "sample_anyrun_report.json"

    result = run_pipeline(report_path, output_dir=tmp_path, write_output=True, timestamp="2026-06-28T10:00:00+00:00")

    output_files = result.metadata["output_files"]
    assert output_files["sigma"]
    assert output_files["wazuh"]
    assert output_files["reports"]
    assert output_files["iocs"]
    assert output_files["navigator"]
    for files in output_files.values():
        for file_path in files:
            assert Path(file_path).exists()


def test_pipeline_accepts_custom_wazuh_id_range() -> None:
    report_path = FIXTURES_DIR / "sample_cuckoo_report.json"

    result = run_pipeline(
        report_path,
        write_output=False,
        wazuh_id_start=130000,
        wazuh_id_end=130100,
        timestamp="2026-06-28T10:00:00+00:00",
    )

    assert result.wazuh_rules
    assert all(130000 <= rule.rule_id <= 130100 for rule in result.wazuh_rules)


def test_cli_single_report_mode_works(tmp_path: Path, capsys) -> None:
    report_path = FIXTURES_DIR / "sample_cape_report.json"

    exit_code = main(["--report", str(report_path), "--output", str(tmp_path), "--no-write"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "behaviors=" in captured.out


def test_cli_accepts_wazuh_id_override_args(tmp_path: Path, capsys) -> None:
    report_path = FIXTURES_DIR / "sample_cape_report.json"

    exit_code = main(
        [
            "--report",
            str(report_path),
            "--output",
            str(tmp_path),
            "--no-write",
            "--wazuh-id-start",
            "131000",
            "--wazuh-id-end",
            "131050",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "wazuh=" in captured.out


def test_batch_mode_handles_all_three_fixtures(tmp_path: Path, capsys) -> None:
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    for source in FIXTURES_DIR.glob("sample_*_report.json"):
        (batch_dir / source.name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    exit_code = main(["--input-dir", str(batch_dir), "--output", str(tmp_path / "out"), "--no-write"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out.count("behaviors=") == 3


def test_batch_mode_returns_error_if_one_report_fails(tmp_path: Path, capsys) -> None:
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()
    good = FIXTURES_DIR / "sample_cuckoo_report.json"
    (batch_dir / good.name).write_text(good.read_text(encoding="utf-8"), encoding="utf-8")
    (batch_dir / "broken.json").write_text('["not","an","object"]', encoding="utf-8")

    exit_code = main(["--input-dir", str(batch_dir), "--no-write"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "error:" in captured.out


def test_pipeline_with_unknown_sandbox_returns_clear_error() -> None:
    try:
        run_pipeline({}, write_output=False)
    except ValueError as exc:
        assert "Could not detect sandbox type" in str(exc)
    else:
        raise AssertionError("Expected unknown sandbox input to raise ValueError")


def test_no_write_does_not_create_artifacts(tmp_path: Path) -> None:
    report_path = FIXTURES_DIR / "sample_cuckoo_report.json"

    run_pipeline(report_path, output_dir=tmp_path, write_output=False)

    assert not any(tmp_path.rglob("*"))


def test_invalid_missing_report_path_returns_clean_error(capsys) -> None:
    exit_code = main(["--report", "missing-file.json", "--no-write"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "error:" in captured.out


def test_slugify_limits_length_and_avoids_reserved_windows_names(tmp_path: Path) -> None:
    report = {
        "info": {"id": 7},
        "target": {"file": {"name": "CON"}},
        "behavior": {"processes": [{"process_name": "helper.exe"}]},
    }

    result = run_pipeline(report, sandbox="cuckoo", output_dir=tmp_path, write_output=True, timestamp="2026-06-28T10:00:00+00:00")

    for generated in result.metadata["output_files"]["wazuh"]:
        assert Path(generated).name.startswith("sample_")
        assert len(Path(generated).stem) <= 80


def test_pipeline_urlhaus_enrichment_tags_matching_iocs(tmp_path: Path) -> None:
    csv_path = tmp_path / "urlhaus.csv"
    csv_path.write_text(
        "# comment\n"
        "1,2026-06-28 00:00:00,http://example.test/health,online,2026-06-28,malware_download,,https://urlhaus.abuse.ch/url/1/,tester\n",
        encoding="utf-8",
    )

    result = run_pipeline(
        FIXTURES_DIR / "sample_cape_report.json",
        write_output=False,
        enrich=True,
        urlhaus_csv=csv_path,
        timestamp="2026-06-28T10:00:00+00:00",
    )

    assert result.metadata["enrichment"]["urlhaus"]["match_count"] >= 1
    assert any("source:urlhaus" in item.tags for item in result.iocs if item.type in {"url", "domain"})
