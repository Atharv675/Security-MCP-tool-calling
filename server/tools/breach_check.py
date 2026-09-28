"""Check whether a password has appeared in known breach dumps.

Uses the Have I Been Pwned "Pwned Passwords" range API ONLY:
    https://api.pwnedpasswords.com/range/{first5}

This is a PASSWORD breach check, not an email breach check. HIBP's email
breach lookup is a separate, paid API and is explicitly out of scope here.
No API key is required or used for this endpoint.

k-anonymity flow (this is the whole point of the design, so it's spelled
out explicitly rather than left implicit in the code below):
  1. SHA1-hash the password LOCALLY.
  2. Send only the FIRST 5 HEX CHARACTERS of that hash to HIBP.
  3. HIBP returns every suffix in its database that shares that 5-char
     prefix, each with a breach count.
  4. Compare the remaining 35 characters LOCALLY against the returned
     suffixes -- nothing but the 5-char prefix ever leaves this process.

The full password and the full hash are NEVER transmitted over the network.
"""

import hashlib

import httpx

from server.tools.rate_limit import SlidingWindowLimiter

_HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_MAX_PASSWORD_LENGTH = 256

# Simple abuse guard so an agent loop can't hammer HIBP -- rejects with a
# structured error once exceeded rather than blocking.
_LIMITER = SlidingWindowLimiter(max_calls=15, window_seconds=60)


def check_password_breach(password: str) -> dict:
    """Check a password against HIBP's Pwned Passwords range API (k-anonymity).

    Does NOT accept or look up emails -- password-only breach checking.
    """
    if not isinstance(password, str) or password == "":
        return {"error": "password must be a non-empty string"}
    if len(password) > _MAX_PASSWORD_LENGTH:
        return {"error": f"password must be at most {_MAX_PASSWORD_LENGTH} characters"}
    if not _LIMITER.check():
        return {"error": "rate limit exceeded, try again shortly"}

    # Full SHA1 hash is computed and kept in-process only.
    sha1_hex = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hex[:5], sha1_hex[5:]

    try:
        # Only the 5-character prefix is ever sent over the network.
        response = httpx.get(
            _HIBP_RANGE_URL.format(prefix=prefix),
            headers={"Add-Padding": "true"},
            timeout=10.0,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        return {"error": f"HIBP request failed: {exc}"}

    times_seen = 0
    for line in response.text.splitlines():
        try:
            returned_suffix, count_str = line.strip().split(":")
        except ValueError:
            continue
        if returned_suffix == suffix:
            times_seen = int(count_str)
            break

    return {"breached": times_seen > 0, "times_seen": times_seen}


if __name__ == "__main__":
    print("password123 ->", check_password_breach("password123"))
    import secrets
    print("random ->", check_password_breach(secrets.token_urlsafe(24)))
