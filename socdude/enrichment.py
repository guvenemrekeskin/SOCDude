"""IOC enrichment against real threat-intel sources.

Hard rule: every value this module returns came from an actual API
response. If a provider has no API key configured, or the call fails
or times out, that provider is simply omitted from the result - never
backfilled with a placeholder. The AI prompt built downstream is
explicitly instructed to only interpret data that is actually present
here, never to invent a score for a source that's missing.

Providers that need no API key (GeoIP via ip-api.com, RDAP, DNS,
URLhaus, MalwareBazaar) always run. Providers that need a key
(VirusTotal, AbuseIPDB, GreyNoise, Shodan, OTX) are skipped until the
corresponding key is set in config.json - see config.example.json.
"""

from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests

from . import state as state_mod

log = logging.getLogger(__name__)


def _get_json(url: str, cfg: Dict[str, Any], **kwargs) -> Optional[Dict[str, Any]]:
    try:
        r = requests.get(url, timeout=cfg["enrichment_timeout_seconds"], **kwargs)
        if r.status_code >= 400:
            log.debug("Enrichment GET %s -> HTTP %s", url, r.status_code)
            return None
        return r.json()
    except Exception as exc:  # noqa: BLE001
        log.debug("Enrichment GET %s failed: %s", url, exc)
        return None


def _post_json(url: str, cfg: Dict[str, Any], **kwargs) -> Optional[Dict[str, Any]]:
    try:
        r = requests.post(url, timeout=cfg["enrichment_timeout_seconds"], **kwargs)
        if r.status_code >= 400:
            return None
        return r.json()
    except Exception as exc:  # noqa: BLE001
        log.debug("Enrichment POST %s failed: %s", url, exc)
        return None


# ---------------------------------------------------------------- IP ----

def geoip(ip: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """ip-api.com - free, no key required. GeoIP/ASN only, nothing sensitive."""
    data = _get_json(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as", cfg)
    if not data or data.get("status") != "success":
        return None
    return {
        "country": data.get("country"), "region": data.get("regionName"),
        "city": data.get("city"), "isp": data.get("isp"),
        "org": data.get("org"), "asn": data.get("as"),
    }


def virustotal_ip(ip: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    key = cfg.get("virustotal_api_key")
    if not key:
        return None
    data = _get_json(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", cfg,
                      headers={"x-apikey": key})
    stats = (data or {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    if not stats:
        return None
    return {
        "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0), "total_engines": sum(stats.values()),
    }


def abuseipdb(ip: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    key = cfg.get("abuseipdb_api_key")
    if not key:
        return None
    data = _get_json("https://api.abuseipdb.com/api/v2/check", cfg,
                      headers={"Key": key, "Accept": "application/json"},
                      params={"ipAddress": ip, "maxAgeInDays": 90})
    d = (data or {}).get("data", {})
    if not d:
        return None
    return {
        "abuse_confidence_score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"), "country_code": d.get("countryCode"),
        "is_tor": d.get("isTor"), "usage_type": d.get("usageType"),
    }


def greynoise(ip: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    key = cfg.get("greynoise_api_key")
    if not key:
        return None
    data = _get_json(f"https://api.greynoise.io/v3/community/{ip}", cfg, headers={"key": key})
    if not data or "noise" not in data:
        return None
    return {
        "noise": data.get("noise"), "riot": data.get("riot"),
        "classification": data.get("classification"), "name": data.get("name"),
    }


def shodan(ip: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    key = cfg.get("shodan_api_key")
    if not key:
        return None
    data = _get_json(f"https://api.shodan.io/shodan/host/{ip}", cfg, params={"key": key})
    if not data:
        return None
    return {
        "open_ports": data.get("ports", []), "org": data.get("org"), "os": data.get("os"),
        "hostnames": data.get("hostnames", []),
        "vulns": list(data.get("vulns", [])) if data.get("vulns") else [],
    }


def rdap_ip(ip: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """RDAP (the modern WHOIS replacement) via rdap.org - no key required."""
    data = _get_json(f"https://rdap.org/ip/{ip}", cfg)
    if not data:
        return None
    return {"name": data.get("name"), "handle": data.get("handle"), "country": data.get("country")}


# ------------------------------------------------------------ domain ----

def virustotal_domain(domain: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    key = cfg.get("virustotal_api_key")
    if not key:
        return None
    data = _get_json(f"https://www.virustotal.com/api/v3/domains/{domain}", cfg,
                      headers={"x-apikey": key})
    stats = (data or {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    if not stats:
        return None
    return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)}


def dns_lookup(domain: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        _, _, addrs = socket.gethostbyname_ex(domain)
        return {"a_records": addrs} if addrs else None
    except Exception:
        return None


def urlhaus_host(domain_or_ip: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """abuse.ch URLhaus - free, no key required."""
    data = _post_json("https://urlhaus-api.abuse.ch/v1/host/", cfg, data={"host": domain_or_ip})
    if not data or data.get("query_status") != "ok":
        return None
    return {"url_count": data.get("url_count"), "blacklists": data.get("blacklists")}


# -------------------------------------------------------------- hash ----

def virustotal_hash(file_hash: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    key = cfg.get("virustotal_api_key")
    if not key:
        return None
    data = _get_json(f"https://www.virustotal.com/api/v3/files/{file_hash}", cfg,
                      headers={"x-apikey": key})
    attrs = (data or {}).get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    if not stats:
        return None
    return {
        "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
        "type_description": attrs.get("type_description"),
        "meaningful_name": attrs.get("meaningful_name"),
    }


def malwarebazaar_hash(file_hash: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """abuse.ch MalwareBazaar - free, no key required."""
    data = _post_json("https://mb-api.abuse.ch/api/v1/", cfg,
                       data={"query": "get_info", "hash": file_hash})
    if not data or data.get("query_status") != "ok":
        return None
    entries = data.get("data", [])
    if not entries:
        return None
    e = entries[0]
    return {"signature": e.get("signature"), "file_type": e.get("file_type"), "first_seen": e.get("first_seen")}


def otx_ip(ip: str, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    key = cfg.get("otx_api_key")
    if not key:
        return None
    data = _get_json(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", cfg,
                      headers={"X-OTX-API-KEY": key})
    if not data:
        return None
    return {"pulse_count": data.get("pulse_info", {}).get("count", 0)}


# --------------------------------------------------------- orchestrator ----

_IP_PROVIDERS = [
    ("GeoIP/ASN", geoip), ("VirusTotal", virustotal_ip), ("AbuseIPDB", abuseipdb),
    ("GreyNoise", greynoise), ("Shodan", shodan), ("RDAP", rdap_ip), ("OTX", otx_ip),
]
_DOMAIN_PROVIDERS = [
    ("VirusTotal", virustotal_domain), ("DNS", dns_lookup), ("URLhaus", urlhaus_host),
]
_HASH_PROVIDERS = [
    ("VirusTotal", virustotal_hash), ("MalwareBazaar", malwarebazaar_hash),
]


def _enrich_one(ioc: str, providers, cfg: Dict[str, Any], db_path: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for source_name, fn in providers:
        cached = state_mod.cache_get(db_path, ioc, source_name, cfg["enrichment_cache_ttl_seconds"])
        if cached is not None:
            if cached:  # don't resurface empty cache entries as if they were data
                result[source_name] = cached
            continue
        try:
            data = fn(ioc, cfg)
        except Exception as exc:  # noqa: BLE001
            log.debug("Provider %s failed for %s: %s", source_name, ioc, exc)
            data = None
        state_mod.cache_set(db_path, ioc, source_name, data or {})
        if data:
            result[source_name] = data
    return result


def enrich_iocs(iocs: Dict[str, Any], cfg: Dict[str, Any], db_path: str) -> Dict[str, Any]:
    """Enrich a capped subset of extracted IOCs in parallel.

    Returns {ioc_value: {source_name: result_dict}}. IOCs with no
    successful lookup from any provider are absent from the result -
    never represented with placeholder data.
    """
    if not cfg.get("enrichment_enabled", True):
        return {}

    cap = cfg["enrichment_max_iocs_per_type"]
    targets: List[Tuple[str, list]] = []
    for ip in iocs.get("public_ips", [])[:cap]:
        targets.append((ip, _IP_PROVIDERS))
    for domain in iocs.get("domains", [])[:cap]:
        targets.append((domain, _DOMAIN_PROVIDERS))
    hashes = (iocs.get("hashes", {}).get("sha256", [])[:cap]
              + iocs.get("hashes", {}).get("sha1", [])[:cap]
              + iocs.get("hashes", {}).get("md5", [])[:cap])
    for h in hashes:
        targets.append((h, _HASH_PROVIDERS))

    if not targets:
        return {}

    results: Dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
        futures = {pool.submit(_enrich_one, ioc, providers, cfg, db_path): ioc
                   for ioc, providers in targets}
        for future in as_completed(futures):
            ioc = futures[future]
            try:
                data = future.result()
            except Exception as exc:  # noqa: BLE001
                log.debug("Enrichment failed entirely for %s: %s", ioc, exc)
                data = {}
            if data:
                results[ioc] = data
    return results


def render_enrichment(enrichment: Dict[str, Any]) -> str:
    if not enrichment:
        return "No enrichment data available (no API keys configured, or all lookups failed/timed out)."
    lines = ["Threat intelligence data actually retrieved (use ONLY this - never invent a score):"]
    for ioc, sources in enrichment.items():
        lines.append(f"\n{ioc}:")
        for source, data in sources.items():
            lines.append(f"  [{source}] {data}")
    return "\n".join(lines)
