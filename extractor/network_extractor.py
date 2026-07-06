"""Network behavior extraction from normalized sandbox reports."""

from __future__ import annotations

import ipaddress
from typing import Any, Mapping
from urllib.parse import urlparse

from core.constants import COMMON_ATTACK_MAPPINGS
from core.models import Behavior
from core.schema import ensure_list, ensure_mapping


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False
    return True


def _hostname_from_uri(uri: str) -> str:
    return urlparse(uri).hostname or ""


def _extract_port(network_item: Mapping[str, Any]) -> int | None:
    for key in ("port", "dst_port", "destination_port", "destinationPort"):
        value = network_item.get(key)
        if value in (None, ""):
            continue
        try:
            return int(str(value).strip())
        except ValueError:
            continue
    uri = str(network_item.get("uri") or network_item.get("url") or "").strip()
    if uri:
        return urlparse(uri).port
    return None


def _ip_behavior(ip_value: str, source: str, network_item: dict[str, Any]) -> Behavior:
    evidence = dict(network_item)
    evidence.setdefault("ip", ip_value)
    port = _extract_port(evidence)
    tags = ["ip_connection"]
    mapping_key = "ip_connection"
    if port and port not in {53, 80, 123, 443, 853}:
        evidence.setdefault("port", port)
        tags.append("non_standard_port")
        mapping_key = "non_standard_port"
    return Behavior(
        category="network",
        description=f"IP connection observed: {ip_value}",
        source=source,
        severity="medium",
        evidence=[evidence],
        tags=tags,
        technique_ids=[COMMON_ATTACK_MAPPINGS["network"][mapping_key]["technique_id"]],
    )


def extract_behaviors(normalized_report: Mapping[str, Any]) -> list[Behavior]:
    """Extract network behaviors from a normalized report."""
    source = str(normalized_report.get("sandbox", "unknown"))
    behaviors: list[Behavior] = []

    for item in ensure_list(normalized_report.get("network")):
        network_item = ensure_mapping(item)
        if not network_item:
            continue

        domain = str(network_item.get("domain") or "").strip()
        if domain:
            if _is_ip_address(domain):
                behaviors.append(_ip_behavior(domain, source, {**network_item, "source_field": "domain"}))
            else:
                behaviors.append(
                    Behavior(
                        category="network",
                        description=f"DNS lookup observed: {domain}",
                        source=source,
                        severity="medium",
                        evidence=[network_item],
                        tags=["dns_query"],
                        technique_ids=[COMMON_ATTACK_MAPPINGS["network"]["dns_query"]["technique_id"]],
                    )
                )

        if "uri" in network_item or "url" in network_item:
            uri = str(network_item.get("uri") or network_item.get("url") or "").strip()
            evidence = dict(network_item)
            hostname = _hostname_from_uri(uri)
            if hostname and _is_ip_address(hostname):
                evidence.setdefault("ip", hostname)
                evidence["host_is_ip"] = True
            tags = ["http_connection"]
            technique_ids = [COMMON_ATTACK_MAPPINGS["network"]["http_beacon"]["technique_id"]]
            port = _extract_port(evidence)
            if port and port not in {53, 80, 123, 443, 853}:
                evidence.setdefault("port", port)
                tags.append("non_standard_port")
                technique_ids.append(COMMON_ATTACK_MAPPINGS["network"]["non_standard_port"]["technique_id"])
            behaviors.append(
                Behavior(
                    category="network",
                    description=f"HTTP connection observed: {uri}",
                    source=source,
                    severity="medium",
                    evidence=[evidence],
                    tags=tags,
                    technique_ids=technique_ids,
                )
            )

        if "ip" in network_item or "ipv6" in network_item:
            ip = str(network_item.get("ip") or network_item.get("ipv6") or "").strip()
            if ip:
                behaviors.append(_ip_behavior(ip, source, network_item))
        elif not any(key in network_item for key in ("domain", "uri", "url")):
            behaviors.append(
                Behavior(
                    category="network",
                    description="Network activity observed",
                    source=source,
                    severity="medium",
                    evidence=[network_item],
                    tags=["network_activity"],
                    technique_ids=[COMMON_ATTACK_MAPPINGS["network"]["http_beacon"]["technique_id"]],
                )
            )

    return behaviors

