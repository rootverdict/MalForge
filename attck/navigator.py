"""ATT&CK Navigator layer generation."""

from __future__ import annotations

from collections import defaultdict

from core.constants import ATTACK_LAYER_VERSION, ATTACK_NAVIGATOR_VERSION, ATTACK_VERSION
from core.models import AttackMapping

CONFIDENCE_STYLE = {
    "high": {"threshold": 0.85, "score": 90, "color": "#d32f2f"},
    "medium": {"threshold": 0.6, "score": 60, "color": "#f9a825"},
    "low": {"threshold": 0.0, "score": 30, "color": "#1976d2"},
}


def _confidence_band(confidence: float) -> str:
    if confidence >= CONFIDENCE_STYLE["high"]["threshold"]:
        return "high"
    if confidence >= CONFIDENCE_STYLE["medium"]["threshold"]:
        return "medium"
    return "low"


def generate_navigator_layer(
    mappings: list[AttackMapping] | None,
    *,
    name: str = "Malware Behavior ATT&CK Layer",
) -> dict[str, object]:
    """Generate an ATT&CK Navigator layer from ATT&CK mappings."""
    techniques: list[dict[str, object]] = []
    if mappings:
        grouped: dict[str, list[AttackMapping]] = defaultdict(list)
        for mapping in mappings:
            grouped[mapping.technique_id].append(mapping)

        for technique_id, technique_mappings in sorted(grouped.items()):
            strongest = max(technique_mappings, key=lambda item: item.confidence)
            band = _confidence_band(strongest.confidence)
            style = CONFIDENCE_STYLE[band]
            comments = sorted({mapping.source_behavior for mapping in technique_mappings})
            techniques.append(
                {
                    "techniqueID": technique_id,
                    "tactic": strongest.tactic.replace("_", "-"),
                    "score": style["score"],
                    "color": style["color"],
                    "comment": "; ".join(comments),
                    "enabled": True,
                }
            )

    return {
        "name": name,
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": ATTACK_NAVIGATOR_VERSION,
            "layer": ATTACK_LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": "Rule-based ATT&CK mappings derived from extracted sandbox behaviors.",
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": False, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "legendItems": [
            {"label": "High confidence", "color": CONFIDENCE_STYLE["high"]["color"]},
            {"label": "Medium confidence", "color": CONFIDENCE_STYLE["medium"]["color"]},
            {"label": "Low confidence", "color": CONFIDENCE_STYLE["low"]["color"]},
        ],
    }
