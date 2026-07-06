"""IOC extraction from normalized reports and behaviors."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from core.models import Behavior, IOC
from core.schema import ensure_list, ensure_mapping

_HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}
_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_hash(hash_type: str, value: Any) -> str | None:
    normalized = _normalize_text(value).lower()
    pattern = _HASH_PATTERNS[hash_type]
    return normalized if pattern.match(normalized) else None


def _normalize_domain(value: Any) -> str | None:
    normalized = _normalize_text(value).lower().rstrip(".")
    if not normalized or "." not in normalized:
        return None
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        return None
    return normalized if _DOMAIN_PATTERN.match(normalized) else None


def _normalize_ipv4(value: Any, *, allow_private: bool = True) -> str | None:
    normalized = _normalize_text(value)
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv4Address):
        return None
    if address.is_loopback or address.is_link_local or address.is_reserved:
        return None
    if not allow_private and address.is_private:
        return None
    return normalized


def _normalize_ipv6(value: Any) -> str | None:
    normalized = _normalize_text(value)
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv6Address):
        return None
    if address.is_loopback or address.is_link_local:
        return None
    return normalized.lower()


def _normalize_url(value: Any) -> str | None:
    normalized = _normalize_text(value)
    if not normalized:
        return None
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https", "ftp", "smb", "tcp"} or not parsed.netloc:
        return None
    return normalized


def _normalize_registry_key(value: Any) -> str | None:
    normalized = _normalize_text(value)
    return normalized if normalized.startswith("HK") else None


def _normalize_file_path(value: Any) -> str | None:
    normalized = _normalize_text(value)
    if not normalized:
        return None
    if ":\\" in normalized or normalized.startswith("/"):
        return normalized
    return None


def _normalize_mutex(value: Any) -> str | None:
    normalized = _normalize_text(value)
    return normalized if normalized else None


def _ioc(
    ioc_type: str,
    value: str | None,
    source: str,
    *,
    confidence: float = 0.5,
    context: dict[str, Any] | None = None,
    tags: list[str] | None = None,
) -> IOC | None:
    if not value:
        return None
    return IOC(
        type=ioc_type,
        value=value,
        source=source,
        confidence=confidence,
        context=context or {},
        tags=tags or [],
    )


def _deduplicate(iocs: Iterable[IOC]) -> list[IOC]:
    seen: set[tuple[str, str]] = set()
    unique: list[IOC] = []
    for item in iocs:
        key = (item.type, item.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def extract_iocs_from_report(normalized_report: Mapping[str, Any]) -> list[IOC]:
    """Extract IOCs from a normalized report dictionary."""
    source = str(normalized_report.get("sandbox", "unknown"))
    collected: list[IOC] = []

    sample = ensure_mapping(normalized_report.get("sample"))
    hashes = ensure_mapping(sample.get("hashes"))
    for hash_type in ("md5", "sha1", "sha256"):
        value = _normalize_hash(hash_type, hashes.get(hash_type))
        ioc = _ioc(hash_type, value, source, confidence=0.9, context={"source_section": "sample.hashes"})
        if ioc:
            collected.append(ioc)

    for item in ensure_list(normalized_report.get("network")):
        network_item = ensure_mapping(item)
        if not network_item:
            continue

        ip_value = _normalize_ipv4(network_item.get("ip"))
        if ip_value:
            collected.append(
                IOC(type="ipv4", value=ip_value, source=source, confidence=0.7, context={"source_section": "network", "raw": network_item}, tags=["network"])
            )

        ipv6_value = _normalize_ipv6(network_item.get("ipv6"))
        if ipv6_value:
            collected.append(
                IOC(type="ipv6", value=ipv6_value, source=source, confidence=0.7, context={"source_section": "network", "raw": network_item}, tags=["network"])
            )

        domain_value = _normalize_domain(network_item.get("domain"))
        if domain_value:
            collected.append(
                IOC(type="domain", value=domain_value, source=source, confidence=0.7, context={"source_section": "network", "raw": network_item}, tags=["network"])
            )
        else:
            domain_ip_value = _normalize_ipv4(network_item.get("domain"))
            if domain_ip_value:
                collected.append(
                    IOC(type="ipv4", value=domain_ip_value, source=source, confidence=0.7, context={"source_section": "network.domain", "raw": network_item}, tags=["network"])
                )

        url_value = _normalize_url(network_item.get("uri") or network_item.get("url"))
        if url_value:
            collected.append(
                IOC(type="url", value=url_value, source=source, confidence=0.7, context={"source_section": "network", "raw": network_item}, tags=["network"])
            )
            parsed = urlparse(url_value)
            domain_from_url = _normalize_domain(parsed.hostname)
            if domain_from_url:
                collected.append(
                    IOC(type="domain", value=domain_from_url, source=source, confidence=0.6, context={"source_section": "network.url_host", "raw": network_item}, tags=["network"])
                )
            else:
                ip_from_url = _normalize_ipv4(parsed.hostname)
                if ip_from_url:
                    collected.append(
                        IOC(type="ipv4", value=ip_from_url, source=source, confidence=0.6, context={"source_section": "network.url_host", "raw": network_item}, tags=["network"])
                    )

    for item in ensure_list(normalized_report.get("files")):
        mapping = ensure_mapping(item)
        path = item if isinstance(item, str) else mapping.get("path") or mapping.get("name")
        file_path = _normalize_file_path(path)
        ioc = _ioc("file_path", file_path, source, confidence=0.6, context={"source_section": "files", "raw": item}, tags=["filesystem"])
        if ioc:
            collected.append(ioc)
        file_hashes = ensure_mapping(mapping.get("hashes"))
        for hash_type in ("md5", "sha1", "sha256"):
            value = _normalize_hash(hash_type, mapping.get(hash_type) or file_hashes.get(hash_type))
            ioc = _ioc(hash_type, value, source, confidence=0.7, context={"source_section": "files.hashes", "raw": item}, tags=["filesystem"])
            if ioc:
                collected.append(ioc)

    for item in ensure_list(normalized_report.get("registry")):
        key = item if isinstance(item, str) else ensure_mapping(item).get("key") or ensure_mapping(item).get("path")
        registry_key = _normalize_registry_key(key)
        ioc = _ioc("registry_key", registry_key, source, confidence=0.6, context={"source_section": "registry", "raw": item}, tags=["registry"])
        if ioc:
            collected.append(ioc)

    metadata = ensure_mapping(normalized_report.get("metadata"))
    for item in ensure_list(metadata.get("mutexes")):
        mutex = _normalize_mutex(item)
        ioc = _ioc("mutex", mutex, source, confidence=0.6, context={"source_section": "metadata.mutexes"}, tags=["mutex"])
        if ioc:
            collected.append(ioc)

    return _deduplicate(collected)


def extract_iocs_from_behaviors(behaviors: list[Behavior] | None) -> list[IOC]:
    """Extract IOCs from behavior evidence."""
    if not behaviors:
        return []

    collected: list[IOC] = []
    for behavior in behaviors:
        for evidence in behavior.evidence:
            if not isinstance(evidence, Mapping):
                continue
            evidence_map = dict(evidence)
            source = behavior.source

            ip_value = _normalize_ipv4(evidence_map.get("ip"))
            if ip_value:
                collected.append(
                    IOC(type="ipv4", value=ip_value, source=source, confidence=0.6, context={"behavior": behavior.description, "category": behavior.category}, tags=[behavior.category])
                )

            ipv6_value = _normalize_ipv6(evidence_map.get("ipv6"))
            if ipv6_value:
                collected.append(
                    IOC(type="ipv6", value=ipv6_value, source=source, confidence=0.6, context={"behavior": behavior.description, "category": behavior.category}, tags=[behavior.category])
                )

            domain_value = _normalize_domain(evidence_map.get("domain"))
            if domain_value:
                collected.append(
                    IOC(type="domain", value=domain_value, source=source, confidence=0.6, context={"behavior": behavior.description, "category": behavior.category}, tags=[behavior.category])
                )
            else:
                domain_ip_value = _normalize_ipv4(evidence_map.get("domain"))
                if domain_ip_value:
                    collected.append(
                        IOC(type="ipv4", value=domain_ip_value, source=source, confidence=0.6, context={"behavior": behavior.description, "category": behavior.category}, tags=[behavior.category])
                    )

            url_value = _normalize_url(evidence_map.get("uri") or evidence_map.get("url"))
            if url_value:
                collected.append(
                    IOC(type="url", value=url_value, source=source, confidence=0.6, context={"behavior": behavior.description, "category": behavior.category}, tags=[behavior.category])
                )

            file_path = _normalize_file_path(evidence_map.get("path"))
            if file_path:
                collected.append(
                    IOC(type="file_path", value=file_path, source=source, confidence=0.6, context={"behavior": behavior.description, "category": behavior.category}, tags=[behavior.category])
                )

            registry_key = _normalize_registry_key(evidence_map.get("key"))
            if registry_key:
                collected.append(
                    IOC(type="registry_key", value=registry_key, source=source, confidence=0.6, context={"behavior": behavior.description, "category": behavior.category}, tags=[behavior.category])
                )

            process_name = _normalize_text(evidence_map.get("process_name"))
            if process_name.lower() == "unknown_process":
                process_name = ""
            if process_name and process_name.lower().endswith((".exe", ".dll", ".bin")):
                collected.append(
                    IOC(type="file_path", value=process_name, source=source, confidence=0.3, context={"behavior": behavior.description, "category": behavior.category}, tags=["process_image"])
                )

    return _deduplicate(collected)


def extract_all_iocs(
    normalized_report: Mapping[str, Any],
    behaviors: list[Behavior] | None = None,
) -> list[IOC]:
    """Extract and combine IOCs from report and behavior sources."""
    combined = extract_iocs_from_report(normalized_report)
    if behaviors:
        combined.extend(extract_iocs_from_behaviors(behaviors))
    return _deduplicate(combined)

