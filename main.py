"""Command-line interface for the local malware behavior detection pipeline."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml
from core.pipeline import run_pipeline


def _load_config(path: str | Path = "config.yaml") -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        return {}
    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data if isinstance(data, dict) else {}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the malware behavior detection generator locally.")
    parser.add_argument("--report", help="Path to a single sandbox JSON report.")
    parser.add_argument("--input-dir", help="Directory containing sandbox JSON reports.")
    parser.add_argument("--sandbox", choices=["cuckoo", "cape", "anyrun", "auto"], default="auto")
    parser.add_argument("--output", default="output", help="Output directory root.")
    parser.add_argument("--no-write", action="store_true", help="Run the pipeline without writing artifacts.")
    parser.add_argument("--enrich", action="store_true", help="Build local enrichment request descriptors for extracted IOCs.")
    parser.add_argument("--urlhaus-csv", help="Path to a local URLhaus CSV export for offline enrichment.")
    parser.add_argument("--wazuh-id-start", type=int, help="Override the starting Wazuh custom rule ID.")
    parser.add_argument("--wazuh-id-end", type=int, help="Override the ending Wazuh custom rule ID.")
    parser.add_argument("--verbose", action="store_true", help="Print additional per-run details.")
    return parser


def _print_summary(result, *, verbose: bool = False) -> None:
    summary = result.metadata["summary"]
    counts = summary["counts"]
    warning_count = counts["validation"]["warning_count"]
    line = (
        f"{result.input_file or result.source}: "
        f"behaviors={sum(counts['behaviors_by_category'].values())} "
        f"iocs={sum(counts['iocs_by_type'].values())} "
        f"attack={counts['attack_technique_count']} "
        f"sigma={counts['sigma_rule_count']} "
        f"wazuh={counts['wazuh_rule_count']} "
        f"warnings={warning_count}"
    )
    print(line)
    if verbose and result.metadata.get("output_files"):
        print(f"  wrote: {result.metadata['output_files']}")


def main(argv: list[str] | None = None) -> int:
    """Run the local pipeline in single-report or batch mode."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    config = _load_config()
    wazuh_config = config.get("wazuh", {}) if isinstance(config.get("wazuh"), dict) else {}
    integrations = config.get("integrations", {}) if isinstance(config.get("integrations"), dict) else {}
    wazuh_id_start = args.wazuh_id_start if args.wazuh_id_start is not None else wazuh_config.get("custom_rule_id_start")
    wazuh_id_end = args.wazuh_id_end if args.wazuh_id_end is not None else wazuh_config.get("custom_rule_id_end")
    wazuh_offset = int(wazuh_config.get("custom_rule_id_offset", 0) or 0)
    if wazuh_id_start is not None and wazuh_id_end is not None:
        wazuh_id_start = int(wazuh_id_start) + wazuh_offset
        wazuh_id_end = int(wazuh_id_end) + wazuh_offset
    urlhaus_csv = args.urlhaus_csv or integrations.get("urlhaus_csv")

    if not args.report and not args.input_dir:
        parser.error("one of --report or --input-dir is required")

    try:
        if args.report:
            result = run_pipeline(
                args.report,
                sandbox=args.sandbox,
                output_dir=args.output,
                write_output=not args.no_write,
                enrich=args.enrich,
                urlhaus_csv=urlhaus_csv,
                wazuh_id_start=wazuh_id_start,
                wazuh_id_end=wazuh_id_end,
            )
            _print_summary(result, verbose=args.verbose)
            return 0

        input_dir = Path(args.input_dir)
        if not input_dir.exists():
            raise FileNotFoundError(f"Input directory does not exist: {input_dir}")
        report_paths = sorted(path for path in input_dir.glob("*.json") if path.is_file())
        if not report_paths:
            raise FileNotFoundError(f"No JSON reports found in: {input_dir}")

        had_errors = False
        for report_path in report_paths:
            try:
                result = run_pipeline(
                    report_path,
                    sandbox=args.sandbox,
                    output_dir=args.output,
                    write_output=not args.no_write,
                    enrich=args.enrich,
                    urlhaus_csv=urlhaus_csv,
                    wazuh_id_start=wazuh_id_start,
                    wazuh_id_end=wazuh_id_end,
                )
                _print_summary(result, verbose=args.verbose)
            except (FileNotFoundError, ValueError) as exc:
                had_errors = True
                print(f"error: {exc}")
        return 1 if had_errors else 0
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
