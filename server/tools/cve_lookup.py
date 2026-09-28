"""Look up CVEs by CVE-ID or keyword using the NVD REST API v2.

Data source: https://services.nvd.nist.gov/rest/json/cves/2.0
Docs: https://nvd.nist.gov/developers/vulnerabilities

Without an API key, NVD enforces 5 requests / 30s; with one (NVD_API_KEY),
the limit is 50 requests / 30s. This module rate-limits to the
unauthenticated limit unless a key is configured (rejecting with a
structured error rather than blocking the call), and caches repeated
lookups in memory for a short TTL to cut down on redundant calls.

NOTE: the exact JSON response shape below (vulnerabilities[].cve.{id,
descriptions,metrics,published}) matches NVD's documented v2 schema, but
this has not been exercised against a live call during development --
treat the parsing as best-effort and re-verify field names against a real
response before relying on this in production.
"""

import re
import time

import httpx

from server.config import settings
from server.tools.rate_limit import SlidingWindowLimiter

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_MIN_QUERY_LENGTH = 2
_MAX_QUERY_LENGTH = 200

_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_TTL_SECONDS = 15 * 60

# Matches NVD's unauthenticated limit (5 requests / 30s). Skipped when
# NVD_API_KEY is set, since the authenticated limit (50/30s) is high
# enough that a portfolio project won't hit it.
_LIMITER = SlidingWindowLimiter(max_calls=5, window_seconds=30)


def _extract_summary(cve_obj: dict) -> dict:
    cve_id = cve_obj.get("id", "unknown")
    descriptions = cve_obj.get("descriptions", [])
    description = next(
        (d.get("value") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value") if descriptions else "",
    )
    metrics = cve_obj.get("metrics", {})
    severity = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            severity = metrics[key][0].get("cvssData", {}).get("baseSeverity")
            break
    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity,
        "published": cve_obj.get("published"),
    }


def lookup_cve(query: str) -> dict:
    """Look up a CVE by ID (e.g. 'CVE-2021-44228') or free-text keyword.

    Returns a list of matching CVE summaries (id, description, severity,
    published date). Results are cached in-memory for 15 minutes.
    """
    if not isinstance(query, str) or query.strip() == "":
        return {"error": "query must be a non-empty string"}
    normalized = query.strip()
    if not (_MIN_QUERY_LENGTH <= len(normalized) <= _MAX_QUERY_LENGTH):
        return {
            "error": f"query must be between {_MIN_QUERY_LENGTH} and {_MAX_QUERY_LENGTH} characters"
        }

    cache_key = normalized.lower()
    cached = _CACHE.get(cache_key)
    if cached and time.monotonic() - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]

    if not settings.nvd_api_key and not _LIMITER.check():
        return {"error": "rate limit exceeded, try again shortly"}

    params: dict[str, str] = {}
    if _CVE_ID_RE.match(normalized):
        params["cveId"] = normalized.upper()
    else:
        params["keywordSearch"] = normalized

    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}

    try:
        response = httpx.get(_NVD_URL, params=params, headers=headers, timeout=15.0)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        return {"error": f"NVD request failed: {exc}"}

    try:
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        results = [_extract_summary(v["cve"]) for v in vulnerabilities if "cve" in v]
    except (ValueError, KeyError) as exc:
        return {"error": f"failed to parse NVD response: {exc}"}

    result = {"query": normalized, "results": results, "total": len(results)}
    _CACHE[cache_key] = (time.monotonic(), result)
    return result


if __name__ == "__main__":
    print(lookup_cve("CVE-2021-44228"))
    print(lookup_cve("log4j"))
