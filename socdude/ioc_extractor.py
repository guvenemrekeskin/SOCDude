"""Deterministic, regex-based IOC extraction.

Design decision: IOCs are extracted and rendered by *code*, not by the
LLM. A model asked to "list the IOCs in this log" will occasionally
normalize, truncate, or under pressure invent one to make the table
look complete. Regex extraction is boring but exact - which is what
matters for something a SOC analyst might paste straight into
VirusTotal.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_URL = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,24})\b"
)
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_USER_AGENT = re.compile(r"User-Agent:\s*([^\r\n]+)", re.IGNORECASE)
_FILE_PATH = re.compile(
    r"(?:[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+"   # Windows path
    r"|/(?:[^/\0\s]+/)*[^/\0\s]+\.[A-Za-z0-9]{1,6})"                  # Unix-ish, needs an extension
)

_MAX_PER_TYPE = 25  # ceiling so one giant log blob can't blow up the table


def _dedup(items: List[str], limit: int = _MAX_PER_TYPE) -> List[str]:
    seen: List[str] = []
    for i in items:
        if i not in seen:
            seen.append(i)
        if len(seen) >= limit:
            break
    return seen


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _walk_json_strings(obj: Any) -> List[str]:
    """Flatten every string value in a (possibly nested) alert dict, so
    IOCs sitting in structured fields (not just full_log) are caught too."""
    out: List[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_walk_json_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_walk_json_strings(v))
    elif isinstance(obj, str):
        out.append(obj)
    return out


def extract_iocs(alert: Dict[str, Any], full_log: str) -> Dict[str, Any]:
    """Extract IOCs from the raw log text and the full alert JSON.

    Public and private IPs are split out separately since they need
    very different downstream handling - nobody wants 10.0.0.5 queried
    against VirusTotal.
    """
    haystacks = [full_log] + _walk_json_strings(alert)
    blob = "\n".join(str(h) for h in haystacks if h)

    all_ips = _dedup(_IPV4.findall(blob))
    public_ips = [ip for ip in all_ips if not _is_private_ip(ip)]
    private_ips = [ip for ip in all_ips if _is_private_ip(ip)]

    urls = _dedup(_URL.findall(blob))

    domain_candidates = _DOMAIN.findall(blob)
    noisy_tlds = {"exe", "dll", "log", "json", "txt", "conf", "py", "sh", "png", "jpg"}
    domains = _dedup([
        d for d in domain_candidates
        if not _IPV4.fullmatch(d)
        and d.rsplit(".", 1)[-1].lower() not in noisy_tlds
    ])

    hashes_sha256 = _dedup(_SHA256.findall(blob))
    sha256_set = set(hashes_sha256)
    # SHA1/MD5 patterns can match substrings of a SHA256 hex string; exclude those.
    hashes_sha1 = _dedup([h for h in _SHA1.findall(blob) if h not in sha256_set])
    sha1_set = set(hashes_sha1)
    hashes_md5 = _dedup([h for h in _MD5.findall(blob) if h not in sha256_set and h not in sha1_set])

    emails = _dedup(_EMAIL.findall(blob))
    macs = _dedup(_MAC.findall(blob))
    user_agents = _dedup(_USER_AGENT.findall(blob), limit=5)

    # File paths: the Unix-style pattern can also match the path portion
    # of a URL (https://host/payload.exe) or a version fragment inside a
    # User-Agent string (curl/7.68.0). Drop any candidate that's actually
    # a substring of something already captured as a URL or User-Agent.
    raw_file_paths = _FILE_PATH.findall(blob)
    file_paths = _dedup([
        p for p in raw_file_paths
        if not any(p in u for u in urls) and not any(p in ua for ua in user_agents)
    ], limit=15)

    return {
        "public_ips": public_ips,
        "private_ips": private_ips,
        "domains": domains,
        "urls": urls,
        "emails": emails,
        "mac_addresses": macs,
        "file_paths": file_paths,
        "user_agents": user_agents,
        "hashes": {
            "sha256": hashes_sha256,
            "sha1": hashes_sha1,
            "md5": hashes_md5,
        },
    }


def render_ioc_table(iocs: Dict[str, Any]) -> str:
    """Plain-text IOC table for the Telegram message."""
    lines: List[str] = []

    def section(title: str, values: List[str]) -> None:
        if not values:
            return
        lines.append(f"{title}:")
        for v in values:
            lines.append(f"  - {v}")

    section("Public IPs", iocs["public_ips"])
    section("Private/internal IPs", iocs["private_ips"])
    section("Domains", iocs["domains"])
    section("URLs", iocs["urls"])
    section("Email addresses", iocs["emails"])
    section("MAC addresses", iocs["mac_addresses"])
    section("File paths", iocs["file_paths"])
    section("User-Agents", iocs["user_agents"])
    section("SHA256 hashes", iocs["hashes"]["sha256"])
    section("SHA1 hashes", iocs["hashes"]["sha1"])
    section("MD5 hashes", iocs["hashes"]["md5"])

    return "\n".join(lines) if lines else "No IOCs extracted from this log line."
