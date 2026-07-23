"""Local review metadata helpers for generated rules."""

from __future__ import annotations

from dataclasses import replace

from core.models import SigmaRule, WazuhRule

ALLOWED_REVIEW_STATES = {"approved", "needs_tuning", "rejected", "unreviewed"}


def create_review_record(
    status: str = "unreviewed",
    *,
    reviewer: str = "",
    notes: str = "",
) -> dict[str, str]:
    """Create a validated review record."""
    normalized_status = status.strip().lower()
    if normalized_status not in ALLOWED_REVIEW_STATES:
        raise ValueError(f"Invalid review status: {status}")
    return {
        "status": normalized_status,
        "reviewer": reviewer.strip(),
        "notes": notes.strip(),
    }


def apply_review_to_rule(
    rule: SigmaRule | WazuhRule,
    review_record: dict[str, str],
) -> SigmaRule | WazuhRule:
    """Return a copy of a rule with review metadata applied."""
    if isinstance(rule, SigmaRule):
        metadata = dict(rule.metadata)
        metadata["review"] = dict(review_record)
        return replace(rule, metadata=metadata)

    options = dict(rule.options)
    options["review"] = dict(review_record)
    return replace(rule, options=options)


def apply_review_to_rules(
    rules: list[SigmaRule | WazuhRule] | None,
    review_record: dict[str, str],
) -> list[SigmaRule | WazuhRule]:
    """Apply review metadata to a list of rules."""
    return [apply_review_to_rule(rule, review_record) for rule in rules or []]
