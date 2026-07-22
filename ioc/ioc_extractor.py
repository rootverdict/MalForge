"""IOC extraction from normalized reports and behaviors."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable, Mapping
from urllib.parse import ParseResult, urlparse

from core.models import Behavior, IOC
from core.schema import ensure_list, ensure_mapping

_HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}
_DOMAIN_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,63}$")
_IPV4_LIKE_PATTERN = re.compile(r"^\d+(?:\.\d+){3}$")
_SUPPORTED_URL_SCHEMES = frozenset({"http", "https", "ftp", "smb", "tcp"})


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_hash(hash_type: str, value: Any) -> str | None:
    normalized = _normalize_text(value).lower()
    pattern = _HASH_PATTERNS[hash_type]
    return normalized if pattern.match(normalized) else None


def _normalize_ipv4(value: Any, *, allow_private: bool = True) -> str | None:
    normalized = _normalize_text(value)
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv4Address):
        return None
    if address.is_loopback or address.is_link_local or address.is_reserved or address.is_unspecified or address.is_multicast:
        return None
    if not allow_private and address.is_private:
        return None
    return str(address)


def _normalize_ipv6(value: Any) -> str | None:
    normalized = _normalize_text(value)
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv6Address):
        return None
    if address.is_loopback or address.is_link_local or address.is_reserved or address.is_unspecified or address.is_multicast:
        return None
    return str(address).lower()


def _normalize_network_host(
    value: Any,
    *,
    allow_single_label: bool = True,
) -> tuple[str, str] | None:
    """Normalize an actionable IP address or syntactically valid DNS hostname."""
    normalized = _normalize_text(value).lower().rstrip(".")
    if not normalized or len(normalized) > 253 or any(char.isspace() for char in normalized):
        return None

    try:
        address = ipaddress.ip_address(normalized.strip("[]"))
    except ValueError:
        address = None

    if address is not None:
        canonical_address = str(address)
        if isinstance(address, ipaddress.IPv4Address):
            ipv4 = _normalize_ipv4(canonical_address)
            return ("ipv4", ipv4) if ipv4 else None
        ipv6 = _normalize_ipv6(canonical_address)
        return ("ipv6", ipv6) if ipv6 else None

    # Do not reinterpret malformed dotted IPv4 values as DNS names.
    if _IPV4_LIKE_PATTERN.fullmatch(normalized):
        return None

    try:
        ascii_name = normalized.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    labels = ascii_name.split(".")
    if not allow_single_label and len(labels) < 2:
        return None
    if not all(
        _DOMAIN_LABEL_PATTERN.fullmatch(label)
        and not label.startswith("-")
        and not label.endswith("-")
        for label in labels
    ):
        return None
    return "domain", ascii_name


def _normalize_domain(value: Any) -> str | None:
    normalized = _normalize_network_host(value, allow_single_label=False)
    if not normalized or normalized[0] != "domain":
        return None
    return normalized[1]


def _parse_network_url(value: Any) -> tuple[str, ParseResult, tuple[str, str]] | None:
    """Parse a supported URL only when its port and host are valid."""
    normalized = _normalize_text(value)
    if not normalized:
        return None
    try:
        parsed = urlparse(normalized)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in _SUPPORTED_URL_SCHEMES
        or not parsed.netloc
        or not hostname
        or (port is not None and not 1 <= port <= 65535)
    ):
        return None
    normalized_host = _normalize_network_host(hostname)
    if not normalized_host:
        return None
    host_type, host_value = normalized_host
    canonical_host = f"[{host_value}]" if host_type == "ipv6" else host_value
    userinfo = ""
    if parsed.username is not None:
        userinfo = parsed.username
        if parsed.password is not None:
            userinfo = f"{userinfo}:{parsed.password}"
        userinfo = f"{userinfo}@"
    canonical_netloc = f"{userinfo}{canonical_host}"
    if port is not None:
        canonical_netloc = f"{canonical_netloc}:{port}"
    canonical_parsed = parsed._replace(scheme=parsed.scheme.lower(), netloc=canonical_netloc)
    return canonical_parsed.geturl(), canonical_parsed, normalized_host


def _normalize_url(value: Any) -> str | None:
    parsed = _parse_network_url(value)
    return parsed[0] if parsed else None


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


_EXPLICIT_TYPE_ALIASES = {
    "ip": "ip",
    "ip_address": "ip",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "domain",
    "hostname": "domain",
    "fqdn": "domain",
    "url": "url",
    "uri": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "file": "file_path",
    "file_path": "file_path",
    "path": "file_path",
    "registry": "registry_key",
    "registry_key": "registry_key",
    "mutex": "mutex",
}


def _normalize_explicit_value(ioc_type: str, value: Any) -> str | None:
    if ioc_type in _HASH_PATTERNS:
        return _normalize_hash(ioc_type, value)
    if ioc_type == "ipv4":
        return _normalize_ipv4(value)
    if ioc_type == "ipv6":
        return _normalize_ipv6(value)
    if ioc_type == "domain":
        return _normalize_domain(value)
    if ioc_type == "url":
        return _normalize_url(value)
    if ioc_type == "file_path":
        return _normalize_file_path(value)
    if ioc_type == "registry_key":
        return _normalize_registry_key(value)
    if ioc_type == "mutex":
        return _normalize_mutex(value)
    return None


def _normalize_explicit_candidate(ioc_type: str, value: Any) -> tuple[str, str] | None:
    if ioc_type == "ip":
        ipv4 = _normalize_ipv4(value)
        if ipv4:
            return "ipv4", ipv4
        ipv6 = _normalize_ipv6(value)
        if ipv6:
            return "ipv6", ipv6
        return None
    normalized = _normalize_explicit_value(ioc_type, value)
    return (ioc_type, normalized) if normalized else None


def _infer_explicit_type(value: Any) -> tuple[str, str] | None:
    for ioc_type in ("md5", "sha1", "sha256", "ipv4", "ipv6", "url", "domain", "registry_key", "file_path"):
        normalized = _normalize_explicit_value(ioc_type, value)
        if normalized:
            return ioc_type, normalized
    return None


def _extract_explicit_iocs(normalized_report: Mapping[str, Any], source: str) -> list[IOC]:
    collected: list[IOC] = []
    for raw_item in ensure_list(normalized_report.get("iocs")):
        if isinstance(raw_item, str):
            inferred = _infer_explicit_type(raw_item)
            if inferred:
                ioc_type, value = inferred
                collected.append(
                    IOC(type=ioc_type, value=value, source=source, confidence=0.8, context={"source_section": "iocs", "raw": raw_item}, tags=["explicit"])
                )
            continue

        item = ensure_mapping(raw_item)
        if not item:
            continue
        declared_type = str(item.get("type") or item.get("ioc_type") or item.get("indicator_type") or "").strip().lower()
        declared_value = item.get("value") or item.get("indicator") or item.get("ioc")
        candidates: list[tuple[str, Any]] = []
        if declared_type and declared_value is not None:
            normalized_type = _EXPLICIT_TYPE_ALIASES.get(declared_type)
            if normalized_type:
                for nested_value in ensure_list(declared_value):
                    candidates.append((normalized_type, nested_value))
        else:
            for key, value in item.items():
                normalized_type = _EXPLICIT_TYPE_ALIASES.get(str(key).strip().lower())
                if normalized_type:
                    for nested_value in ensure_list(value):
                        candidates.append((normalized_type, nested_value))

        for ioc_type, raw_value in candidates:
            normalized_candidate = _normalize_explicit_candidate(ioc_type, raw_value)
            if normalized_candidate:
                normalized_type, value = normalized_candidate
                collected.append(
                    IOC(type=normalized_type, value=value, source=source, confidence=0.8, context={"source_section": "iocs", "raw": raw_item}, tags=["explicit"])
                )
    return collected


def _deduplicate(iocs: Iterable[IOC]) -> list[IOC]:
    keys_in_order: list[tuple[str, str]] = []
    best_by_key: dict[tuple[str, str], IOC] = {}
    for item in iocs:
        key = (item.type, item.value)
        current = best_by_key.get(key)
        if current is None:
            keys_in_order.append(key)
            best_by_key[key] = item
        elif item.confidence > current.confidence:
            best_by_key[key] = item
    return [best_by_key[key] for key in keys_in_order]


def extract_iocs_from_report(normalized_report: Mapping[str, Any]) -> list[IOC]:
    """Extract IOCs from a normalized report dictionary."""
    source = str(normalized_report.get("sandbox", "unknown"))
    collected: list[IOC] = _extract_explicit_iocs(normalized_report, source)

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

        parsed_url = _parse_network_url(network_item.get("uri") or network_item.get("url"))
        if parsed_url:
            url_value, _, normalized_host = parsed_url
            collected.append(
                IOC(type="url", value=url_value, source=source, confidence=0.7, context={"source_section": "network", "raw": network_item}, tags=["network"])
            )
            host_type, host_value = normalized_host
            if host_type == "domain" and _normalize_domain(host_value):
                collected.append(
                    IOC(type="domain", value=host_value, source=source, confidence=0.6, context={"source_section": "network.url_host", "raw": network_item}, tags=["network"])
                )
            elif host_type in {"ipv4", "ipv6"}:
                collected.append(
                    IOC(type=host_type, value=host_value, source=source, confidence=0.6, context={"source_section": "network.url_host", "raw": network_item}, tags=["network"])
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

            parsed_url = _parse_network_url(evidence_map.get("uri") or evidence_map.get("url"))
            if parsed_url:
                url_value, _, normalized_host = parsed_url
                collected.append(
                    IOC(type="url", value=url_value, source=source, confidence=0.6, context={"behavior": behavior.description, "category": behavior.category}, tags=[behavior.category])
                )
                host_type, host_value = normalized_host
                if host_type == "domain" and _normalize_domain(host_value):
                    collected.append(
                        IOC(type="domain", value=host_value, source=source, confidence=0.5, context={"behavior": behavior.description, "category": behavior.category}, tags=[behavior.category])
                    )
                elif host_type in {"ipv4", "ipv6"}:
                    collected.append(
                        IOC(type=host_type, value=host_value, source=source, confidence=0.5, context={"behavior": behavior.description, "category": behavior.category}, tags=[behavior.category])
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

