"""Parse a log file or raw log text and flag suspicious patterns.

Detectors are simple, explainable regexes -- not a full IDS -- covering:
  - repeated/failed authentication attempts
  - port-scan-like signatures (many distinct ports touched by one source)
  - SQL-injection payload patterns
"""

import re
from collections import defaultdict
from typing import Optional

from pydantic import BaseModel, model_validator

_FAILED_LOGIN_RE = re.compile(
    r"(failed password|authentication failure|invalid user|failed login)",
    re.IGNORECASE,
)
_SQLI_RE = re.compile(
    r"(\bunion\s+select\b|\bor\s+1\s*=\s*1\b|'\s*or\s*'1'\s*=\s*'1|--\s*$|;\s*drop\s+table)",
    re.IGNORECASE,
)
_PORT_SCAN_LINE_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?\bport[= ](?P<port>\d{1,5})\b",
    re.IGNORECASE,
)

_PORT_SCAN_DISTINCT_PORT_THRESHOLD = 5


class LogAnalysisRequest(BaseModel):
    file_path: Optional[str] = None
    raw_text: Optional[str] = None

    @model_validator(mode="after")
    def _exactly_one_source(self) -> "LogAnalysisRequest":
        provided = [v for v in (self.file_path, self.raw_text) if v]
        if len(provided) != 1:
            raise ValueError("exactly one of file_path or raw_text must be provided")
        return self


def _load_text(request: LogAnalysisRequest) -> str:
    if request.raw_text is not None:
        return request.raw_text
    with open(request.file_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def analyze_log(request: LogAnalysisRequest) -> dict:
    """Analyze log text/file for failed logins, port-scan signatures, and SQLi patterns.

    Returns structured findings: {line_number, severity, reason, matched_text}.
    """
    try:
        text = _load_text(request)
    except OSError as exc:
        return {"error": f"could not read log file: {exc}"}

    findings: list[dict] = []
    ip_ports: dict[str, set[str]] = defaultdict(set)
    failed_login_counts: dict[str, int] = defaultdict(int)

    lines = text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        if _FAILED_LOGIN_RE.search(line):
            findings.append({
                "line_number": line_number,
                "severity": "medium",
                "reason": "failed authentication attempt",
                "matched_text": line.strip()[:200],
            })
            ip_match = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", line)
            if ip_match:
                failed_login_counts[ip_match.group(0)] += 1

        if _SQLI_RE.search(line):
            findings.append({
                "line_number": line_number,
                "severity": "high",
                "reason": "possible SQL injection payload",
                "matched_text": line.strip()[:200],
            })

        port_match = _PORT_SCAN_LINE_RE.search(line)
        if port_match:
            ip_ports[port_match.group("ip")].add(port_match.group("port"))

    for ip, count in failed_login_counts.items():
        if count >= 5:
            findings.append({
                "line_number": None,
                "severity": "high",
                "reason": f"{count} failed login attempts from {ip} (possible brute force)",
                "matched_text": ip,
            })

    for ip, ports in ip_ports.items():
        if len(ports) >= _PORT_SCAN_DISTINCT_PORT_THRESHOLD:
            findings.append({
                "line_number": None,
                "severity": "high",
                "reason": f"{ip} touched {len(ports)} distinct ports (possible port scan)",
                "matched_text": ip,
            })

    return {"findings": findings, "total_findings": len(findings), "lines_scanned": len(lines)}


if __name__ == "__main__":
    sample = (
        "Jan 1 12:00:01 sshd: Failed password for invalid user admin from 10.0.0.5\n"
        "Jan 1 12:00:02 sshd: Failed password for invalid user root from 10.0.0.5\n"
        "GET /login?user=' OR '1'='1 HTTP/1.1\n"
        "Jan 1 12:00:03 scan from 10.0.0.9 port=22\n"
        "Jan 1 12:00:04 scan from 10.0.0.9 port=23\n"
        "Jan 1 12:00:05 scan from 10.0.0.9 port=80\n"
        "Jan 1 12:00:06 scan from 10.0.0.9 port=443\n"
        "Jan 1 12:00:07 scan from 10.0.0.9 port=8080\n"
    )
    print(analyze_log(LogAnalysisRequest(raw_text=sample)))
