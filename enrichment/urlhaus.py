"""Offline URLhaus CSV enrichment helpers."""

from __future__ import annotations

import csv
from pathlib import Path
from urllib.parse import urlparse

from core.models import IOC


def load_urlhaus_indicators(csv_path: str | Path) -> tuple[set[str], set[str]]:
    """Load URL and domain indicators from a URLhaus CSV export."""
    path = Path(csv_path)
    urls: set[str] = set()
    domains: set[str] = set()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(line for line in handle if not line.startswith("#"))
        for row in reader:
            if len(row) < 2:
                continue
            url_value = row[2].strip() if len(row) > 2 else row[1].strip()
            if not url_value:
                continue
            urls.add(url_value)
            hostname = urlparse(url_value).hostname
            if hostname:
                domains.add(hostname.lower())
    return urls, domains


def enrich_iocs_with_urlhaus(iocs: list[IOC], csv_path: str | Path) -> dict[str, object]:
    """Tag matching URL and domain IOCs using an offline URLhaus CSV dataset."""
    urls, domains = load_urlhaus_indicators(csv_path)
    matches: list[dict[str, str]] = []

    for item in iocs:
        matched = False
        if item.type == "url" and item.value in urls:
            matched = True
        elif item.type == "domain" and item.value.lower() in domains:
            matched = True
        if not matched:
            continue
        if "source:urlhaus" not in item.tags:
            item.tags.append("source:urlhaus")
        item.confidence = max(item.confidence, 0.9)
        item.context["urlhaus_match"] = True
        matches.append({"type": item.type, "value": item.value})

    return {
        "provider": "urlhaus",
        "csv_path": str(Path(csv_path)),
        "match_count": len(matches),
        "matches": matches,
        "network_call_performed": False,
    }
