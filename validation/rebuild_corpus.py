"""Rebuild the internet-derived validation corpus from its manifest.

The original URLhaus-derived sandbox reports were never checked in, which left
the artifact snapshot impossible to regenerate. The manifest does preserve every
input field, so this script reconstructs the reports from it and reruns the
pipeline. That keeps the corpus reproducible offline and pinned to the same 50
indicators, so re-running after a code change shows exactly what changed.

Usage (from the repository root):

    python validation/rebuild_corpus.py                 # rebuild in place
    python validation/rebuild_corpus.py --output DIR    # rebuild elsewhere
    python validation/rebuild_corpus.py --check         # verify only, no writes

Safety: reads a local JSON manifest only. No network call, no sample execution.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from urllib.parse import urlsplit

VALIDATION_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = VALIDATION_DIR.parent
MANIFEST_PATH = VALIDATION_DIR / "internet_validation_manifest_50.json"
DEFAULT_OUTPUT = VALIDATION_DIR / "internet_outputs_50"

sys.path.insert(0, str(PROJECT_ROOT))

from core.pipeline import run_pipeline  # noqa: E402
from extractor import is_non_windows_text  # noqa: E402

# Pinned so rebuilds stay byte-identical apart from deliberate code changes.
REBUILD_TIMESTAMP = "2026-07-01T10:00:00+00:00"
SYNTHETIC_PID = 9001
COMMAND_SUFFIX = "--urlhaus-validation"


def _port_from_url(url: str) -> int | None:
    try:
        return urlsplit(url).port
    except ValueError:
        return None


def build_report(entry: dict[str, object]) -> dict[str, object]:
    """Reconstruct the Cuckoo-shaped report for one manifest entry."""
    sample_name = str(entry["sample_name"])
    url = str(entry.get("url") or "")
    host = str(entry.get("host") or "")
    tags = str(entry.get("tags") or "")

    http_entry: dict[str, object] = {"uri": url, "host": host}
    port = _port_from_url(url)
    if port is not None:
        http_entry["port"] = port

    # Samples tagged elf/mips/Mozi/iot/gafgyt were modelled as Linux drops under
    # /tmp; everything else landed in a Windows user-writable download folder.
    # Windows executables recorded that download path twice (payload path and
    # dropped file, which coincide). Reproducing the duplicate matters: it
    # yields two file behaviors that collapse to one Sigma rule, which is what
    # the original snapshot recorded.
    if is_non_windows_text(tags):
        files = [f"/tmp/{sample_name}"]
    else:
        download_path = f"C:\\Users\\Public\\Downloads\\{sample_name}"
        files = [download_path, download_path] if sample_name.lower().endswith(".exe") else [download_path]

    return {
        "info": {
            "sandbox": "cuckoo",
            "urlhaus_id": entry.get("urlhaus_id"),
            "threat": entry.get("threat"),
            "url_status": entry.get("url_status"),
            "tags": tags,
        },
        "target": {"file": {"name": sample_name}},
        "behavior": {
            "processes": [
                {
                    "process_name": sample_name,
                    "pid": SYNTHETIC_PID,
                    "command_line": f"{sample_name} {COMMAND_SUFFIX}",
                }
            ],
            "summary": {"files": files},
        },
        "network": {
            "domains": [{"domain": host}] if host else [],
            "http": [http_entry] if url else [],
        },
        "signatures": [],
    }


def load_manifest() -> list[dict[str, object]]:
    entries = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"Manifest must be a non-empty JSON list: {MANIFEST_PATH}")
    return entries


def _write_summaries(
    entries: list[dict[str, object]],
    totals: dict[str, int],
    techniques: set[str],
    registry: dict[str, int],
) -> None:
    """Refresh the aggregate summary files so they match the rebuilt corpus."""
    payload = {
        "source": "URLhaus recent CSV",
        "source_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "safety_scope": "public CSV metadata only; no malware binaries, no detonation, no live sample execution",
        "rebuilt_by": "validation/rebuild_corpus.py",
        "rebuild_timestamp": REBUILD_TIMESTAMP,
        "reports": len(entries),
        "successful_runs": len(entries),
        "failed_runs": 0,
        "aggregate_behaviors": totals["behaviors"],
        "aggregate_iocs": totals["iocs"],
        "aggregate_sigma_rules": totals["sigma"],
        "aggregate_wazuh_rules": totals["wazuh"],
        "validation_warnings": totals["warnings"],
        "validation_errors": totals["errors"],
        "unique_attack_techniques": sorted(techniques),
        "unique_wazuh_rule_ids": len(set(registry.values())),
    }
    (VALIDATION_DIR / "internet_validation_summary_50.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    lines = [
        "# Internet-Derived 50 Report Validation Summary",
        "",
        f"Regenerated by `validation/rebuild_corpus.py` at a pinned timestamp of `{REBUILD_TIMESTAMP}`.",
        "Inputs are reconstructed from `internet_validation_manifest_50.json`, so this",
        "run is reproducible offline and pinned to the same 50 indicators.",
        "",
        f"- Source: {payload['source']}",
        f"- Source URL: {payload['source_url']}",
        f"- Safety scope: {payload['safety_scope']}.",
        f"- Input reports reconstructed: {payload['reports']}",
        f"- Successful CLI runs: {payload['successful_runs']}",
        f"- Failed CLI runs: {payload['failed_runs']}",
        f"- Aggregate behaviors: {payload['aggregate_behaviors']}",
        f"- Aggregate IOCs: {payload['aggregate_iocs']}",
        f"- Aggregate Sigma rules: {payload['aggregate_sigma_rules']}",
        f"- Aggregate Wazuh rules: {payload['aggregate_wazuh_rules']}",
        f"- Unique Wazuh rule IDs: {payload['unique_wazuh_rule_ids']}",
        f"- Validation errors: {payload['validation_errors']}",
        f"- Validation warnings: {payload['validation_warnings']}",
        f"- Unique ATT&CK techniques: {len(payload['unique_attack_techniques'])} "
        f"({', '.join(payload['unique_attack_techniques'])})",
        "",
        "## Notes",
        "",
        "- Validation warnings are advisory, not failures. They flag weak rule levels,",
        "  missing ATT&CK tags, and selectors built on common process images.",
        "- Platform-aware generation: elf/mips/Mozi/iot samples emit Linux/generic rules",
        "  instead of Windows/Sysmon rules.",
        "- Raw IP values in domain-like fields are classified as IP/network C2 evidence,",
        "  not DNS/domain evidence or Remote Services lateral movement.",
        "- URL-only source metadata carries no payload hashes, so reports record missing",
        "  MD5/SHA1/SHA256 as a source-data limitation.",
        "",
    ]
    (VALIDATION_DIR / "internet_validation_summary_50.md").write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Artifact output root.")
    parser.add_argument("--check", action="store_true", help="Report counts without writing artifacts.")
    parser.add_argument("--keep-inputs", help="Also write the reconstructed reports to this directory.")
    args = parser.parse_args(argv)

    entries = load_manifest()
    output_root = Path(args.output)

    if not args.check and output_root.exists():
        shutil.rmtree(output_root)

    if args.keep_inputs:
        inputs_dir = Path(args.keep_inputs)
        inputs_dir.mkdir(parents=True, exist_ok=True)

    totals = {"behaviors": 0, "iocs": 0, "sigma": 0, "wazuh": 0, "warnings": 0, "errors": 0}
    registry: dict[str, int] = {}
    techniques: set[str] = set()

    for entry in entries:
        report = build_report(entry)
        if args.keep_inputs:
            (Path(args.keep_inputs) / str(entry["file"])).write_text(
                json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
            )
        result = run_pipeline(
            report,
            sandbox="cuckoo",
            output_dir=output_root,
            write_output=not args.check,
            timestamp=REBUILD_TIMESTAMP,
            wazuh_id_registry=registry,
        )
        counts = result.metadata["summary"]["counts"]
        totals["behaviors"] += sum(counts["behaviors_by_category"].values())
        totals["iocs"] += sum(counts["iocs_by_type"].values())
        totals["sigma"] += counts["sigma_rule_count"]
        totals["wazuh"] += counts["wazuh_rule_count"]
        totals["warnings"] += counts["validation"]["warning_count"]
        totals["errors"] += sum(len(item.errors) for item in result.validation_results)
        techniques.update(result.metadata["summary"]["artifacts"]["attack_techniques"])

    if not args.check:
        _write_summaries(entries, totals, techniques, registry)

    print(f"reports          : {len(entries)}")
    print(f"behaviors        : {totals['behaviors']}")
    print(f"iocs             : {totals['iocs']}")
    print(f"sigma rules      : {totals['sigma']}")
    print(f"wazuh rules      : {totals['wazuh']}")
    print(f"validation warns : {totals['warnings']}")
    print(f"validation errors: {totals['errors']}")
    print(f"unique wazuh ids : {len(set(registry.values()))} of {len(registry)}")
    return 1 if totals["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
