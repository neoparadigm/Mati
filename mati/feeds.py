"""OSINT feed fetchers for threat intelligence data.

All feeds are free and require no tenant access. API keys are optional
for most sources (improves rate limits where noted).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

logger = logging.getLogger("mati.feeds")

_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


async def fetch_cisa_kev(days: int = 7) -> list[dict[str, Any]]:
    """Fetch CISA Known Exploited Vulnerabilities added in the last N days.

    Source: https://github.com/cisagov/kev-data (CC0 license, updated daily)
    No API key required.
    """
    url = (
        "https://raw.githubusercontent.com/cisagov/kev-data/"
        "main/known_exploited_vulnerabilities.json"
    )
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url)
        resp.raise_for_status()

    data = resp.json()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    recent = [
        vuln for vuln in data.get("vulnerabilities", [])
        if vuln.get("dateAdded", "") >= cutoff
    ]
    logger.info("CISA KEV: %d new entries in last %d days", len(recent), days)
    return recent


async def fetch_cvedb_top(
    limit: int = 20,
    sort_by: str = "epss",
) -> list[dict[str, Any]]:
    """Fetch top CVEs from CVEDB (Shodan).

    Free, no API key, no account required.
    """
    url = "https://cvedb.shodan.io/cves"
    params = {"sort_by": sort_by, "order": "desc", "limit": limit}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()

    cves = resp.json().get("cves", [])
    logger.info("CVEDB: fetched %d CVEs sorted by %s", len(cves), sort_by)
    return cves


async def fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for a list of CVE IDs.

    Free, no API key. Returns dict of {cve_id: epss_score}.
    """
    if not cve_ids:
        return {}

    url = "https://api.first.org/data/v1/epss"
    scores: dict[str, float] = {}

    # API accepts comma-separated CVE IDs (batch of 100)
    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i : i + 100]
        params = {"cve": ",".join(batch)}
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()

        for entry in resp.json().get("data", []):
            scores[entry["cve"]] = float(entry.get("epss", 0))

    logger.info("EPSS: fetched scores for %d CVEs", len(scores))
    return scores


async def fetch_nvd_recent(
    api_key: str = "",
    days: int = 7,
    severity: str = "HIGH",
) -> list[dict[str, Any]]:
    """Fetch recently modified CVEs from NIST NVD.

    Free. API key optional but recommended (50 req/30s vs 5 req/30s).
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "lastModStartDate": start,
        "lastModEndDate": end,
        "cvssV3Severity": severity,
        "resultsPerPage": 50,
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url, params=params, headers=headers)
        resp.raise_for_status()

    vulns = resp.json().get("vulnerabilities", [])
    logger.info("NVD: %d %s+ CVEs modified in last %d days", len(vulns), severity, days)
    return vulns


async def fetch_github_advisories(
    token: str = "",
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Fetch recent GitHub security advisories.

    Free with GitHub token (recommended for rate limits).
    """
    url = "https://api.github.com/advisories"
    params = {"per_page": limit, "sort": "published", "direction": "desc"}
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url, params=params, headers=headers)
        resp.raise_for_status()

    advisories = resp.json()
    logger.info("GitHub Advisory: fetched %d advisories", len(advisories))
    return advisories


async def fetch_github_exploits(
    cve_id: str,
    token: str = "",
) -> list[dict[str, Any]]:
    """Search GitHub for public exploit/PoC code for a CVE.

    Free with GitHub token.
    """
    url = "https://api.github.com/search/repositories"
    params = {
        "q": f"{cve_id} exploit OR poc",
        "sort": "updated",
        "order": "desc",
        "per_page": 5,
    }
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url, params=params, headers=headers)
        resp.raise_for_status()

    items = resp.json().get("items", [])
    logger.info("GitHub PoC: %d repos found for %s", len(items), cve_id)
    return items


async def fetch_shodan_internetdb(ip: str) -> dict[str, Any]:
    """Query Shodan InternetDB for open ports and vulns on an IP.

    Free, no API key, no account required.
    """
    url = f"https://internetdb.shodan.io/{ip}"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url)
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()

    data = resp.json()
    logger.info("Shodan InternetDB: %s — %d ports open", ip, len(data.get("ports", [])))
    return data


async def fetch_crt_sh(domain: str, days: int = 7) -> list[dict[str, Any]]:
    """Fetch certificate transparency logs for a domain.

    Free, no API key, no account required.
    """
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json", "exclude": "expired"}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()

    certs = resp.json() if resp.text.strip() else []
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    recent = [
        c for c in certs
        if c.get("entry_timestamp", "")[:10] >= cutoff
    ]
    logger.info("crt.sh: %d recent certs for %s", len(recent), domain)
    return recent


async def fetch_dns_record(domain: str, record_type: str = "TXT") -> list[str]:
    """Fetch DNS records via Google DNS JSON API.

    Free, no API key, no rate limit for reasonable use.
    Used for DMARC, SPF, MTA-STS, BIMI, DNSSEC checks.
    """
    url = "https://dns.google/resolve"
    params = {"name": domain, "type": record_type}
    if record_type == "A":
        params["do"] = "true"  # request DNSSEC validation

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()

    data = resp.json()
    answers = data.get("Answer", [])
    return [a.get("data", "") for a in answers]


async def fetch_otx_pulses(
    api_key: str = "",
    days: int = 1,
) -> list[dict[str, Any]]:
    """Fetch recent threat pulses from AlienVault OTX.

    Free with API key (sign up at otx.alienvault.com).
    """
    if not api_key:
        return []

    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    params = {"limit": 20, "modified_since": since}
    headers = {"X-OTX-API-KEY": api_key}

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url, params=params, headers=headers)
        resp.raise_for_status()

    pulses = resp.json().get("results", [])
    logger.info("OTX: %d pulses in last %d days", len(pulses), days)
    return pulses


async def fetch_threatfox_iocs(days: int = 1) -> list[dict[str, Any]]:
    """Fetch recent IOCs from Abuse.ch ThreatFox.

    Free, no API key required.
    """
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "get_iocs", "days": days}

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()

    data = resp.json()
    iocs = data.get("data", []) if data.get("query_status") == "ok" else []
    logger.info("ThreatFox: %d IOCs in last %d days", len(iocs), days)
    return iocs
