"""Core data models for normalized malware behavior analysis artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


def _normalize_severity(value: str) -> str:
    severity = value.strip().lower()
    valid = {"informational", "low", "medium", "high", "critical"}
    if severity not in valid:
        raise ValueError(f"Unsupported severity: {value}")
    return severity


def _bounded_confidence(value: float) -> float:
    if not 0.0 <= value <= 1.0:
        raise ValueError("Confidence must be between 0.0 and 1.0")
    return value


@dataclass(slots=True)
class Behavior:
    """Normalized malware behavior extracted from a sandbox report."""

    category: str
    description: str
    source: str
    severity: str = "medium"
    evidence: list[dict[str, Any]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.severity = _normalize_severity(self.severity)


@dataclass(slots=True)
class IOC:
    """Indicator of compromise extracted from a report."""

    type: str
    value: str
    source: str
    confidence: float = 0.5
    context: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.confidence = _bounded_confidence(self.confidence)


@dataclass(slots=True)
class SigmaRule:
    """Generated Sigma rule representation."""

    title: str
    rule_id: str
    description: str
    logsource: dict[str, Any]
    detection: dict[str, Any]
    level: str = "medium"
    status: str = "experimental"
    author: str = "malware-behavior-detection-generator"
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.level = _normalize_severity(self.level)


@dataclass(slots=True)
class WazuhRule:
    """Generated Wazuh rule representation."""

    rule_id: int
    level: int
    description: str
    group: str = "malware_behavior_detection"
    decoded_as: str | None = None
    if_sid: int | None = None
    fields: dict[str, str] = field(default_factory=dict)
    mitre_ids: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AttackMapping:
    """ATT&CK technique mapping for a behavior."""

    technique_id: str
    technique_name: str
    tactic: str
    source_behavior: str
    confidence: float = 0.5
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.confidence = _bounded_confidence(self.confidence)


@dataclass(slots=True)
class ValidationResult:
    """Validation outcome for generated rules."""

    is_valid: bool
    validator: str
    score: float = 0.0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RiskScore:
    """Risk score assigned to a pipeline result."""

    score: float
    severity: str
    rationale: list[str] = field(default_factory=list)
    factors: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = _normalize_severity(self.severity)
        if self.score < 0:
            raise ValueError("Risk score cannot be negative")
        if self.score > 100:
            raise ValueError("Risk score cannot exceed 100")


@dataclass(slots=True)
class PipelineResult:
    """Container for the full normalized pipeline output."""

    source: str
    input_file: str | None = None
    behaviors: list[Behavior] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    sigma_rules: list[SigmaRule] = field(default_factory=list)
    wazuh_rules: list[WazuhRule] = field(default_factory=list)
    attack_mappings: list[AttackMapping] = field(default_factory=list)
    validation_results: list[ValidationResult] = field(default_factory=list)
    risk_score: RiskScore | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the pipeline result into plain Python types."""
        return asdict(self)
