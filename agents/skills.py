"""Skill definitions shared by the A2A specialist servers and the
orchestrator's A2APool -- single source of truth for skill id, description,
and the JSON Schema an orchestrator uses when asking Gemini to fill in
arguments.

A2A's AgentSkill (v0.3 spec, as shipped in a2a-sdk 1.1.2's compat layer --
see client/a2a_pool.py for how this was grounded) has no structured
input-schema field, only free-text description/examples -- so the concrete
JSON Schema Gemini needs lives here rather than being transmitted over A2A.

SECURITY_SKILLS maps skill id -> the underlying MCP tool name it wraps (see
agents/security_specialist.py). REPORT_SKILLS has no MCP tool underneath --
report-generation is pure Gemini synthesis (agents/report_writer_specialist.py).
"""

SECURITY_SKILLS = {
    "password-strength-check": {
        "tool": "password_strength",
        "description": "Score a password's strength using character-set entropy. Input: {password: str}.",
        "parameters": {
            "type": "object",
            "properties": {"password": {"type": "string"}},
            "required": ["password"],
        },
    },
    "password-hashing": {
        "tool": "hash_password",
        "description": (
            "Hash text with MD5, SHA1, SHA256, or bcrypt. "
            "Input: {text: str, algorithm: 'md5'|'sha1'|'sha256'|'bcrypt'}."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "algorithm": {"type": "string", "enum": ["md5", "sha1", "sha256", "bcrypt"]},
            },
            "required": ["text", "algorithm"],
        },
    },
    "password-hash-verification": {
        "tool": "verify_password_hash",
        "description": (
            "Verify text matches a given hash under an algorithm. "
            "Input: {text: str, hashed: str, algorithm: 'md5'|'sha1'|'sha256'|'bcrypt'}."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "hashed": {"type": "string"},
                "algorithm": {"type": "string", "enum": ["md5", "sha1", "sha256", "bcrypt"]},
            },
            "required": ["text", "hashed", "algorithm"],
        },
    },
    "credential-breach-check": {
        "tool": "breach_check",
        "description": (
            "Check whether a PASSWORD has appeared in known breach dumps (HIBP k-anonymity). "
            "Makes an outbound network call. Input: {password: str}."
        ),
        "parameters": {
            "type": "object",
            "properties": {"password": {"type": "string"}},
            "required": ["password"],
        },
    },
    "vulnerability-lookup": {
        "tool": "cve_lookup",
        "description": (
            "Look up CVE(s) by CVE-ID or free-text keyword (NVD API). "
            "Makes an outbound network call. Input: {query: str}."
        ),
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    "log-analysis": {
        "tool": "log_analyzer",
        "description": (
            "Analyze raw log text for failed logins, port-scan-like signatures, and SQLi "
            "payload patterns. Input: {raw_text: str}."
        ),
        "parameters": {
            "type": "object",
            "properties": {"raw_text": {"type": "string"}},
            "required": ["raw_text"],
        },
    },
}

REPORT_SKILLS = {
    "report-generation": {
        "description": (
            "Turn raw security findings into a structured report (Summary, "
            "Findings, Recommendations). Input: {target: str, findings: str}."
        ),
        "parameters": {
            "type": "object",
            "properties": {"target": {"type": "string"}, "findings": {"type": "string"}},
            "required": ["target", "findings"],
        },
    },
}

# Skills that trigger a real outbound call and must be approved by the user
# before the orchestrator delegates to them -- checked against the
# UNDERLYING tool name via A2APool.original_name(), so this reuses
# client/agent.py's existing SENSITIVE_TOOLS set unchanged.
SENSITIVE_SKILLS = {"credential-breach-check", "vulnerability-lookup"}

ALL_SKILLS: dict[str, dict] = {**SECURITY_SKILLS, **REPORT_SKILLS}
