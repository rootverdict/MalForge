"""Tests for local enrichment helper modules."""

from core.models import IOC
from enrichment.misp import build_lookup_request as build_misp_lookup_request
from enrichment.urlhaus import enrich_iocs_with_urlhaus, load_urlhaus_indicators
from enrichment.virustotal import build_lookup_request as build_virustotal_lookup_request


def test_virustotal_lookup_request_is_local_only() -> None:
    request = build_virustotal_lookup_request("sha256", "a" * 64)

    assert request["provider"] == "virustotal"
    assert request["network_call_performed"] is False
    assert request["enabled"] is False


def test_misp_lookup_request_tracks_configuration_without_network_calls() -> None:
    request = build_misp_lookup_request("domain", "example.test", url="https://misp.local", api_key="token")

    assert request["provider"] == "misp"
    assert request["enabled"] is True
    assert request["network_call_performed"] is False


def test_urlhaus_loader_and_enrichment_work_offline(tmp_path) -> None:
    csv_path = tmp_path / "urlhaus.csv"
    csv_path.write_text(
        "# comment\n"
        "1,2026-06-28 00:00:00,http://example.test/health,online,2026-06-28,malware_download,,https://urlhaus.abuse.ch/url/1/,tester\n",
        encoding="utf-8",
    )

    urls, domains = load_urlhaus_indicators(csv_path)
    assert "http://example.test/health" in urls
    assert "example.test" in domains

    iocs = [
        IOC(type="url", value="http://example.test/health", source="cape"),
        IOC(type="domain", value="example.test", source="cape"),
        IOC(type="domain", value="safe.test", source="cape"),
    ]
    result = enrich_iocs_with_urlhaus(iocs, csv_path)

    assert result["provider"] == "urlhaus"
    assert result["match_count"] == 2
    assert "source:urlhaus" in iocs[0].tags
    assert iocs[0].confidence == 0.9
