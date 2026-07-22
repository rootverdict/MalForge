"""Network behavior extraction from normalized sandbox reports."""

from __future__ import annotations

from typing import Any, Mapping

from core.constants import COMMON_ATTACK_MAPPINGS
from core.models import Behavior
from core.schema import ensure_list, ensure_mapping
from ioc.ioc_extractor import _normalize_network_host, _parse_network_url

_COMMON_STANDARD_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 445, 465, 587, 853, 993, 995}
_PROTOCOL_STANDARD_PORTS = {
    "http": {80},
    "https": {443},
    "ftp": {20, 21},
    "smb": {139, 445},
}


def _extract_port(network_item: Mapping[str, Any]) -> int | None:
    for key in ("port", "dst_port", "destination_port", "destinationPort"):
        value = network_item.get(key)
        if value in (None, ""):
            continue
        try:
            port = int(str(value).strip())
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            return port
    uri = str(network_item.get("uri") or network_item.get("url") or "").strip()
    if uri:
        parsed_url = _parse_network_url(uri)
        if parsed_url:
            return parsed_url[1].port
    return None


def _ip_behavior(ip_value: str, source: str, network_item: dict[str, Any]) -> Behavior:
    evidence = dict(network_item)
    evidence.setdefault("ip", ip_value)
    port = _extract_port(evidence)
    tags = ["ip_connection"]
    technique_ids: list[str] = []
    if port and port not in _COMMON_STANDARD_PORTS:
        evidence.setdefault("port", port)
        tags.append("non_standard_port")
        technique_ids.append(COMMON_ATTACK_MAPPINGS["network"]["non_standard_port"]["technique_id"])
    return Behavior(
        category="network",
        description=f"IP connection observed: {ip_value}",
        source=source,
        severity="medium",
        evidence=[evidence],
        tags=tags,
        technique_ids=technique_ids,
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
            normalized_host = _normalize_network_host(domain)
            if normalized_host and normalized_host[0] in {"ipv4", "ipv6"}:
                normalized_ip = normalized_host[1]
                behaviors.append(
                    _ip_behavior(
                        normalized_ip,
                        source,
                        {**network_item, "domain": normalized_ip, "source_field": "domain"},
                    )
                )
            elif normalized_host and normalized_host[0] == "domain":
                normalized_domain = normalized_host[1]
                behaviors.append(
                    Behavior(
                        category="network",
                        description=f"DNS lookup observed: {normalized_domain}",
                        source=source,
                        severity="medium",
                        evidence=[{**network_item, "domain": normalized_domain}],
                        tags=["dns_query"],
                        technique_ids=[COMMON_ATTACK_MAPPINGS["network"]["dns_query"]["technique_id"]],
                    )
                )

        if "uri" in network_item or "url" in network_item:
            uri = str(network_item.get("uri") or network_item.get("url") or "").strip()
            parsed_url = _parse_network_url(uri)
            if parsed_url:
                normalized_uri, parsed_uri, normalized_host = parsed_url
                scheme = parsed_uri.scheme.lower()
                hostname_type, hostname = normalized_host
                evidence = dict(network_item)
                evidence["uri" if "uri" in evidence else "url"] = normalized_uri
                if hostname_type == "ipv4":
                    evidence.setdefault("ip", hostname)
                    evidence["host_is_ip"] = True
                elif hostname_type == "ipv6":
                    evidence.setdefault("ipv6", hostname)
                    evidence["host_is_ip"] = True
                if scheme in {"http", "https"}:
                    mapping_key = "http_beacon"
                    protocol_label = "HTTP"
                elif scheme == "ftp":
                    mapping_key = "file_transfer_protocol"
                    protocol_label = "FTP"
                elif scheme == "smb":
                    mapping_key = "smb"
                    protocol_label = "SMB"
                else:
                    mapping_key = None
                    protocol_label = "TCP"
                tags = [f"{scheme}_connection"]
                technique_ids = (
                    [COMMON_ATTACK_MAPPINGS["network"][mapping_key]["technique_id"]]
                    if mapping_key is not None
                    else []
                )
                port = _extract_port(evidence)
                standard_ports = _PROTOCOL_STANDARD_PORTS.get(scheme, _COMMON_STANDARD_PORTS)
                if port and port not in standard_ports:
                    evidence.setdefault("port", port)
                    tags.append("non_standard_port")
                    technique_ids.append(COMMON_ATTACK_MAPPINGS["network"]["non_standard_port"]["technique_id"])
                behaviors.append(
                    Behavior(
                        category="network",
                        description=f"{protocol_label} connection observed: {normalized_uri}",
                        source=source,
                        severity="medium",
                        evidence=[evidence],
                        tags=tags,
                        technique_ids=technique_ids,
                    )
                )

        if "ip" in network_item or "ipv6" in network_item:
            ip = str(network_item.get("ip") or network_item.get("ipv6") or "").strip()
            normalized_ip = _normalize_network_host(ip) if ip else None
            if normalized_ip and normalized_ip[0] in {"ipv4", "ipv6"}:
                behaviors.append(_ip_behavior(normalized_ip[1], source, network_item))
        elif not any(key in network_item for key in ("domain", "uri", "url")):
            behaviors.append(
                Behavior(
                    category="network",
                    description="Network activity observed",
                    source=source,
                    severity="medium",
                    evidence=[network_item],
                    tags=["network_activity"],
                    technique_ids=[],
                )
            )

    return behaviors

