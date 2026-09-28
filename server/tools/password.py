"""Password strength scoring based on character-set entropy."""

import math
import re
from typing import Literal

Verdict = Literal["weak", "medium", "strong"]

_COMMON_PASSWORDS = {
    "password", "password123", "123456", "12345678", "qwerty", "letmein",
    "admin", "welcome", "monkey", "abc123", "iloveyou", "123456789",
}


def _charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 32
    return size or 1


def check_password_strength(password: str) -> dict:
    """Score a password's strength using character-set (Shannon) entropy.

    Returns a structured verdict rather than prose so callers can branch on it.
    """
    if not isinstance(password, str) or password == "":
        return {"error": "password must be a non-empty string"}

    charset = _charset_size(password)
    entropy_bits = round(len(password) * math.log2(charset), 2)

    reasons: list[str] = []
    if len(password) < 8:
        reasons.append("shorter than 8 characters")
    if not re.search(r"[a-z]", password):
        reasons.append("missing lowercase letters")
    if not re.search(r"[A-Z]", password):
        reasons.append("missing uppercase letters")
    if not re.search(r"[0-9]", password):
        reasons.append("missing digits")
    if not re.search(r"[^a-zA-Z0-9]", password):
        reasons.append("missing special characters")
    if password.lower() in _COMMON_PASSWORDS:
        reasons.append("matches a commonly used/breached password")

    if password.lower() in _COMMON_PASSWORDS or entropy_bits < 28:
        verdict: Verdict = "weak"
    elif entropy_bits < 60 or reasons:
        verdict = "medium"
    else:
        verdict = "strong"

    return {
        "verdict": verdict,
        "entropy_bits": entropy_bits,
        "length": len(password),
        "reasons": reasons or ["meets all baseline criteria"],
    }


if __name__ == "__main__":
    for pw in ["password123", "Tr0ub4dor&3", "x7!kQ2$mZp9#Lw4v"]:
        print(pw, "->", check_password_strength(pw))
