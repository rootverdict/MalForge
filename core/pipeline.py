"""Local end-to-end pipeline orchestration and output helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
import re
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Mapping, MutableMapping

from attck.mapper import map_behaviors_to_attack
from attck.navigator import generate_navigator_layer
from converters.wazuh_converter import convert_sigma_to_wazuh, wazuh_rules_to_xml
from core.constants import WAZUH_RULE_ID_END, WAZUH_RULE_ID_START
from core.models import PipelineResult, RiskScore
from core.schema import detect_sandbox, load_json_report
from extractor import extract_behaviors
from generators.sigma_generator import generate_sigma_rules, rule_to_dict
from ingestion.anyrun import parse_report as parse_anyrun_report
from ingestion.cape import parse_report as parse_cape_report
from ingestion.cuckoo import parse_report as parse_cuckoo_report
from ioc.ioc_extractor import extract_all_iocs
from quality.risk_scorer import score_rule
from quality.test_event_generator import generate_test_events
from quality.validator import validate_sigma_rules, validate_wazuh_rules
from reporting.report_generator import generate_markdown_report
from reporting.summary import build_summary
from review.reviewer import apply_review_to_rules, create_review_record
from review.versioner import _now_iso
from review.versioner import version_rules
from enrichment.virustotal import build_lookup_request as build_virustotal_lookup_request
from enrichment.misp import build_lookup_request as build_misp_lookup_request
from enrichment.urlhaus import enrich_iocs_with_urlhaus

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

PARSER_MAP = {
    "cuckoo": parse_cuckoo_report,
    "cape": parse_cape_report,
    "anyrun": parse_anyrun_report,
}

_WINDOWS_RESERVED = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    }
)


def _slugify(value: str, max_length: int = 80) -> str:
    slug = "".join(char.lower() if char.isalnum() else "_" for char in value)
    while "__" in slug:
        slug = slug.replace("__", "_")
    slug = slug.strip("_") or "report"
    if slug in _WINDOWS_RESERVED:
        slug = f"sample_{slug}"
    return slug[:max_length]


def _derive_summary_risk(risk_scores: list[RiskScore]) -> RiskScore | None:
    if not risk_scores:
        return None
    sorted_scores = sorted(item.score for item in risk_scores)
    count = len(sorted_scores)
    p90_index = min(count - 1, max(0, -(-count * 9 // 10) - 1))
    p90_value = sorted_scores[p90_index]
    top_n = max(1, count // 10)
    top_avg = sum(sorted_scores[-top_n:]) / top_n
    representative = round((p90_value + top_avg) / 2, 4)
    representative = max(0.0, min(100.0, representative))
    if representative >= 85:
        severity = "critical"
    elif representative >= 70:
        severity = "high"
    elif representative >= 45:
        severity = "medium"
    elif representative >= 20:
        severity = "low"
    else:
        severity = "informational"
    return RiskScore(
        score=representative,
        severity=severity,
        rationale=[
            f"P90 score across {count} rules: {p90_value}.",
            f"Top-decile average ({top_n} rule(s)): {round(top_avg, 4)}.",
            "Representative is the midpoint of p90 and top-decile average.",
        ],
        factors={
            "rule_count": count,
            "p90_score": p90_value,
            "top_n": top_n,
            "top_avg": round(top_avg, 4),
        },
    )


def _resolve_report_input(report_input: str | Path | Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    if isinstance(report_input, Mapping):
        return dict(report_input), None
    report_path = Path(report_input)
    if not report_path.exists():
        raise FileNotFoundError(f"Report path does not exist: {report_path}")
    return load_json_report(report_path), str(report_path)


def _valid_sha256(value: Any) -> str | None:
    normalized = str(value or "").strip().lower()
    return normalized if re.fullmatch(r"[a-f0-9]{64}", normalized) else None


def _report_fingerprint(report: Mapping[str, Any]) -> str:
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _output_base_name(sample_name: str, report_fingerprint: str) -> str:
    return f"{_slugify(sample_name, max_length=63)}_{report_fingerprint[:12]}"


def _wazuh_registry_path(output_dir: str | Path) -> Path:
    return Path(output_dir) / "wazuh" / ".rule_ids.json"


def _load_wazuh_id_registry(output_dir: str | Path) -> dict[str, int]:
    path = _wazuh_registry_path(output_dir)
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read Wazuh ID registry: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Wazuh ID registry must be a JSON object: {path}")
    registry: dict[str, int] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"Wazuh ID registry contains an invalid entry: {key!r}={value!r}")
        registry[key] = value
    if len(set(registry.values())) != len(registry):
        raise ValueError(f"Wazuh ID registry contains duplicate numeric IDs: {path}")
    return registry


def _write_wazuh_id_registry(output_dir: str | Path, registry: Mapping[str, int]) -> None:
    path = _wazuh_registry_path(output_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f"{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(dict(sorted(registry.items())), handle, indent=2)
            handle.write("\n")
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def write_pipeline_outputs(
    result: PipelineResult,
    output_dir: str | Path,
    *,
    base_name: str = "report",
) -> dict[str, list[str]]:
    """Write pipeline artifacts under the configured output directory only."""
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    safe_base_name = _slugify(str(base_name))

    file_map: dict[str, list[str]] = {
        "sigma": [],
        "wazuh": [],
        "test_events": [],
        "reports": [],
        "iocs": [],
        "navigator": [],
    }

    sigma_dir = output_root / "sigma"
    for rule in result.sigma_rules:
        payload = rule_to_dict(rule)
        if yaml is not None:
            sigma_path = sigma_dir / f"{safe_base_name}_{rule.rule_id}.yml"
            _write_text(sigma_path, yaml.safe_dump(payload, sort_keys=False))
        else:
            sigma_path = sigma_dir / f"{safe_base_name}_{rule.rule_id}.json"
            _write_json(sigma_path, payload)
        file_map["sigma"].append(str(sigma_path))

    if result.wazuh_rules:
        wazuh_path = output_root / "wazuh" / f"{safe_base_name}.xml"
        _write_text(wazuh_path, wazuh_rules_to_xml(result.wazuh_rules))
        file_map["wazuh"].append(str(wazuh_path))

    test_event_path = output_root / "test_events" / f"{safe_base_name}.json"
    _write_json(test_event_path, result.metadata.get("test_events", {}))
    file_map["test_events"].append(str(test_event_path))

    report_path = output_root / "reports" / f"{safe_base_name}_report.md"
    _write_text(report_path, str(result.metadata.get("markdown_report", "")))
    file_map["reports"].append(str(report_path))

    summary_path = output_root / "reports" / f"{safe_base_name}_summary.json"
    _write_json(summary_path, result.metadata.get("summary", {}))
    file_map["reports"].append(str(summary_path))

    iocs_json_path = output_root / "iocs" / f"{safe_base_name}_iocs.json"
    iocs_txt_path = output_root / "iocs" / f"{safe_base_name}_iocs.txt"
    _write_json(iocs_json_path, [asdict(item) for item in result.iocs])
    _write_text(iocs_txt_path, "\n".join(f"{item.type}: {item.value}" for item in result.iocs))
    file_map["iocs"].extend([str(iocs_json_path), str(iocs_txt_path)])

    navigator_path = output_root / "navigator" / f"{safe_base_name}_navigator_layer.json"
    _write_json(navigator_path, result.metadata.get("navigator_layer", {}))
    file_map["navigator"].append(str(navigator_path))
    return file_map


def run_pipeline(
    report_input: str | Path | Mapping[str, Any],
    *,
    sandbox: str = "auto",
    output_dir: str | Path = "output",
    write_output: bool = True,
    timestamp: str | None = None,
    enrich: bool = False,
    urlhaus_csv: str | Path | None = None,
    virustotal_api_key: str | None = None,
    misp_url: str | None = None,
    misp_api_key: str | None = None,
    wazuh_id_start: int | None = None,
    wazuh_id_end: int | None = None,
    wazuh_id_registry: MutableMapping[str, int] | None = None,
) -> PipelineResult:
    """Run the full local pipeline on a sandbox report."""
    raw_report, input_path = _resolve_report_input(report_input)
    detected_sandbox = detect_sandbox(raw_report)
    if sandbox == "auto":
        sandbox_name = detected_sandbox
    else:
        if detected_sandbox != "unknown" and detected_sandbox != sandbox:
            raise ValueError(
                f"Forced sandbox type '{sandbox}' does not match detected report type '{detected_sandbox}'"
            )
        sandbox_name = sandbox
    if sandbox_name == "unknown":
        raise ValueError("Could not detect sandbox type from report")
    if sandbox_name not in PARSER_MAP:
        raise ValueError(f"Unsupported sandbox type: {sandbox_name}")
    run_timestamp = timestamp or _now_iso()
    report_fingerprint = _report_fingerprint(raw_report)
    if wazuh_id_start is not None or wazuh_id_end is not None:
        if wazuh_id_start is None or wazuh_id_end is None:
            raise ValueError("Both wazuh_id_start and wazuh_id_end must be provided together")
        if wazuh_id_start <= 0 or wazuh_id_end <= wazuh_id_start:
            raise ValueError("Wazuh rule ID range must satisfy start > 0 and end > start")
    active_wazuh_id_range = range(
        wazuh_id_start if wazuh_id_start is not None else WAZUH_RULE_ID_START,
        (wazuh_id_end if wazuh_id_end is not None else WAZUH_RULE_ID_END) + 1,
    )

    normalized_report = PARSER_MAP[sandbox_name](raw_report)
    behaviors = extract_behaviors(normalized_report)
    iocs = extract_all_iocs(normalized_report, behaviors)
    attack_mappings = map_behaviors_to_attack(behaviors)
    navigator_layer = generate_navigator_layer(
        attack_mappings,
        name=f"{normalized_report.get('sample', {}).get('name', 'Sample')} ATT&CK Layer",
    )

    review_record = create_review_record("unreviewed")
    sigma_rules = generate_sigma_rules(behaviors, attack_mappings)
    sigma_rules = [rule for rule in apply_review_to_rules(sigma_rules, review_record) if hasattr(rule, "rule_id")]
    sample_hash = _valid_sha256(normalized_report.get("sample", {}).get("hashes", {}).get("sha256"))
    sigma_rules = [rule for rule in version_rules(sigma_rules, timestamp=run_timestamp, source_report_hash=sample_hash) if hasattr(rule, "rule_id")]

    active_wazuh_registry = wazuh_id_registry
    if active_wazuh_registry is None and write_output:
        active_wazuh_registry = _load_wazuh_id_registry(output_dir)
    wazuh_rules = convert_sigma_to_wazuh(
        sigma_rules,
        id_registry=active_wazuh_registry,
        id_namespace=report_fingerprint,
        id_range=active_wazuh_id_range,
    )
    wazuh_rules = [rule for rule in apply_review_to_rules(wazuh_rules, review_record) if hasattr(rule, "rule_id")]
    wazuh_rules = [rule for rule in version_rules(wazuh_rules, timestamp=run_timestamp, source_report_hash=sample_hash) if hasattr(rule, "rule_id")]

    validation_results = validate_sigma_rules(sigma_rules) + validate_wazuh_rules(wazuh_rules)
    risk_scores = [score_rule(rule) for rule in [*sigma_rules, *wazuh_rules]]
    aggregate_risk = _derive_summary_risk(risk_scores)
    test_events = {
        "sigma": {rule.rule_id: generate_test_events(rule) for rule in sigma_rules},
        "wazuh": {str(rule.rule_id): generate_test_events(rule) for rule in wazuh_rules},
    }
    enrichment = {}
    if enrich:
        enrichment = {
            "virustotal": [build_virustotal_lookup_request(item.type, item.value, virustotal_api_key) for item in iocs],
            "misp": [build_misp_lookup_request(item.type, item.value, misp_url, misp_api_key) for item in iocs],
        }
        if urlhaus_csv:
            enrichment["urlhaus"] = enrich_iocs_with_urlhaus(iocs, urlhaus_csv)

    summary = build_summary(
        normalized_report=normalized_report,
        behaviors=behaviors,
        iocs=iocs,
        attack_mappings=attack_mappings,
        sigma_rules=sigma_rules,
        wazuh_rules=wazuh_rules,
        validation_results=validation_results,
        risk_scores=risk_scores,
        review_records=[review_record],
        navigator_layer=navigator_layer,
        generated_at=run_timestamp,
    )
    markdown_report = generate_markdown_report(summary=summary)

    result = PipelineResult(
        source=sandbox_name,
        input_file=input_path,
        behaviors=behaviors,
        iocs=iocs,
        sigma_rules=sigma_rules,
        wazuh_rules=wazuh_rules,
        attack_mappings=attack_mappings,
        validation_results=validation_results,
        risk_score=aggregate_risk,
        metadata={
            "normalized_report": normalized_report,
            "navigator_layer": navigator_layer,
            "summary": summary,
            "markdown_report": markdown_report,
            "test_events": test_events,
            "enrichment": enrichment,
            "review_records": [review_record],
            "risk_scores": [asdict(item) for item in risk_scores],
            "report_fingerprint": report_fingerprint,
            "output_files": {},
        },
    )

    if write_output:
        sample_name = str(normalized_report.get("sample", {}).get("name") or Path(input_path or "report").stem)
        if active_wazuh_registry is not None:
            _write_wazuh_id_registry(output_dir, active_wazuh_registry)
        result.metadata["output_files"] = write_pipeline_outputs(
            result,
            output_dir,
            base_name=_output_base_name(sample_name, report_fingerprint),
        )

    return result
