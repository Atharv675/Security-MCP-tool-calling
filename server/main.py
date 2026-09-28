"""FastMCP server exposing the cybersecurity toolkit over Streamable HTTP."""

from typing import Literal

# pyrefly: ignore [missing-import]
from fastmcp import FastMCP
# pyrefly: ignore [missing-import]
from fastmcp.server.auth import StaticTokenVerifier

from server.config import settings
from server.tools.breach_check import check_password_breach
from server.tools.cve_lookup import lookup_cve
from server.tools.hashing import hash_text, verify_hash
from server.tools.log_analyzer import LogAnalysisRequest, analyze_log
from server.tools.password import check_password_strength
from server.tools.scan_history import get_history, record_scan

if not settings.mcp_auth_token:
    raise RuntimeError(
        "MCP_AUTH_TOKEN must be set -- refusing to start an unauthenticated "
        "security-tools server. Set it in .env (see .env.example)."
    )

# StaticTokenVerifier is dev/prototyping-grade (tokens live in plain text in
# memory) -- appropriate for this portfolio project, not for production use.
_auth = StaticTokenVerifier(
    tokens={settings.mcp_auth_token: {"client_id": "toolkit-client", "scopes": []}}
)

mcp = FastMCP("security-toolkit", auth=_auth)


@mcp.tool()
def password_strength(password: str) -> dict:
    """Score a password's strength using character-set entropy.

    Call this when the user asks whether a password is strong/weak, wants
    an entropy score, or wants concrete reasons a password is weak (too
    short, missing character classes, a commonly used password, etc).
    Returns {verdict: weak|medium|strong, entropy_bits, length, reasons}
    or {error: str} on invalid input.
    """
    try:
        result = check_password_strength(password)
    except Exception as exc:  # noqa: BLE001 - never let an exception cross the MCP boundary
        result = {"error": f"password_strength failed: {exc}"}
    record_scan(
        "password_strength", {"password": password}, "error" if "error" in result else "ok",
        str(result),
    )
    return result


@mcp.tool()
def hash_password(text: str, algorithm: Literal["md5", "sha1", "sha256", "bcrypt"]) -> dict:
    """Hash text with MD5, SHA1, SHA256, or bcrypt.

    Call this when the user wants to hash a password or string. md5/sha1/
    sha256 are fast digests (not for password storage); bcrypt is a slow,
    salted KDF appropriate for storing password hashes. Returns
    {algorithm, hash} or {error: str} on invalid input.
    """
    try:
        result = hash_text(text, algorithm)
    except Exception as exc:  # noqa: BLE001
        result = {"error": f"hash_password failed: {exc}"}
    record_scan(
        "hash_password", {"text": text, "algorithm": algorithm},
        "error" if "error" in result else "ok", str(result),
    )
    return result


@mcp.tool()
def verify_password_hash(
    text: str, hashed: str, algorithm: Literal["md5", "sha1", "sha256", "bcrypt"]
) -> dict:
    """Verify that a piece of text matches a given hash under an algorithm.

    Call this when the user wants to check whether a password/string
    matches a previously produced hash. Returns {algorithm, matches: bool}
    or {error: str} on invalid input.
    """
    try:
        result = verify_hash(text, hashed, algorithm)
    except Exception as exc:  # noqa: BLE001
        result = {"error": f"verify_password_hash failed: {exc}"}
    record_scan(
        "verify_password_hash", {"text": text, "hashed": hashed, "algorithm": algorithm},
        "error" if "error" in result else "ok", str(result),
    )
    return result


@mcp.tool()
def breach_check(password: str) -> dict:
    """Check whether a PASSWORD has appeared in known breach dumps.

    Uses the HIBP Pwned Passwords range API with k-anonymity: only the
    first 5 characters of the password's SHA1 hash are ever sent over the
    network; the full password and full hash never leave this process.
    This is password-only breach checking, NOT an email breach lookup.
    Call this when the user asks if a password has been breached/leaked/
    pwned, or wants to know how many times a password has appeared in
    known breaches. Returns {breached: bool, times_seen: int} or
    {error: str} on failure.
    """
    try:
        result = check_password_breach(password)
    except Exception as exc:  # noqa: BLE001
        result = {"error": f"breach_check failed: {exc}"}
    record_scan(
        "breach_check", {"password": password}, "error" if "error" in result else "ok",
        str(result),
    )
    return result


@mcp.tool()
def cve_lookup(query: str) -> dict:
    """Look up CVE(s) by CVE-ID (e.g. 'CVE-2021-44228') or free-text keyword.

    Call this when the user asks about a specific vulnerability, wants
    details on a CVE ID, or wants to search for vulnerabilities related to
    a product/technology name. Uses the NVD public API, rate-limited to
    its unauthenticated rate limit, with a short-lived in-memory cache for
    repeated queries. Returns {query, results: [...], total} or
    {error: str} on failure.
    """
    try:
        result = lookup_cve(query)
    except Exception as exc:  # noqa: BLE001
        result = {"error": f"cve_lookup failed: {exc}"}
    record_scan(
        "cve_lookup", {"query": query}, "error" if "error" in result else "ok",
        f"total={result.get('total')}" if "error" not in result else str(result),
    )
    return result


@mcp.tool()
def log_analyzer(file_path: str | None = None, raw_text: str | None = None) -> dict:
    """Analyze a log file or raw log text for suspicious security patterns.

    Provide exactly one of file_path or raw_text. Detects repeated/failed
    login attempts (possible brute force), port-scan-like signatures (many
    distinct ports touched by one source IP), and SQL-injection payload
    patterns. Call this when the user wants a log file or log excerpt
    analyzed for security issues. Returns
    {findings: [{line_number, severity, reason, matched_text}, ...],
    total_findings, lines_scanned} or {error: str} on invalid input.
    """
    try:
        request = LogAnalysisRequest(file_path=file_path, raw_text=raw_text)
    except Exception as exc:  # noqa: BLE001 - pydantic ValidationError, etc.
        result = {"error": f"invalid input: {exc}"}
        record_scan("log_analyzer", {"file_path": file_path}, "error", str(result))
        return result
    try:
        result = analyze_log(request)
    except Exception as exc:  # noqa: BLE001
        result = {"error": f"log_analyzer failed: {exc}"}
    record_scan(
        "log_analyzer", {"file_path": file_path}, "error" if "error" in result else "ok",
        f"total_findings={result.get('total_findings')}" if "error" not in result else str(result),
    )
    return result


@mcp.resource("scan://history", description="Recent tool invocations (most recent first, up to 50).")
def scan_history() -> list[dict]:
    return get_history()


@mcp.prompt()
def generate_security_report(target: str, findings: str) -> str:
    """Turn raw tool findings into a structured, readable security report for `target`."""
    return (
        f"You are a security analyst. Write a concise, structured security report "
        f"for target: {target}.\n\n"
        f"Raw findings to incorporate:\n{findings}\n\n"
        f"Structure the report with: Summary, Findings (severity-ranked), Recommendations."
    )


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host=settings.mcp_host, port=settings.mcp_port)
