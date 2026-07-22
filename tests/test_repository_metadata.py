"""Tests for packaging and repository-local metadata."""

from __future__ import annotations

from pathlib import Path
import tomllib


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_setuptools_package_discovery_is_explicit() -> None:
    metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    includes = set(metadata["tool"]["setuptools"]["packages"]["find"]["include"])

    assert {
        "attck*",
        "converters*",
        "core*",
        "enrichment*",
        "extractor*",
        "generators*",
        "ingestion*",
        "ioc*",
        "quality*",
        "reporting*",
        "review*",
    } <= includes


def test_packaged_cli_includes_main_module_and_script_entrypoint() -> None:
    metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert metadata["tool"]["setuptools"]["py-modules"] == ["main"]
    assert metadata["project"]["scripts"]["malforge"] == "main:main"


def test_make_clean_preserves_wazuh_id_registry() -> None:
    makefile = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")
    clean_recipe = makefile.split("clean:", maxsplit=1)[1]

    assert "! -name '.rule_ids.json'" in clean_recipe


def test_generated_handbook_is_ignored() -> None:
    ignored_entries = {
        line.strip()
        for line in (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert "MALFORGE_COMPLETE_PROJECT_HANDBOOK.md" in ignored_entries
