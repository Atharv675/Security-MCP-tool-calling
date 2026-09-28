"""Hash text with MD5/SHA1/SHA256/bcrypt, and verify text against a hash."""

import hashlib
from typing import Literal

import bcrypt

Algorithm = Literal["md5", "sha1", "sha256", "bcrypt"]

_DIGEST_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
}


def hash_text(text: str, algorithm: Algorithm) -> dict:
    """Hash `text` with the given algorithm.

    md5/sha1/sha256 are fast digests (not suitable for password storage).
    bcrypt is a slow, salted KDF suitable for password storage; each call
    produces a different hash for the same input because of the random salt.
    """
    if not isinstance(text, str) or text == "":
        return {"error": "text must be a non-empty string"}
    if algorithm not in ("md5", "sha1", "sha256", "bcrypt"):
        return {"error": f"unsupported algorithm: {algorithm}"}

    if algorithm == "bcrypt":
        hashed = bcrypt.hashpw(text.encode("utf-8"), bcrypt.gensalt())
        return {"algorithm": algorithm, "hash": hashed.decode("utf-8")}

    digest = _DIGEST_ALGORITHMS[algorithm](text.encode("utf-8")).hexdigest()
    return {"algorithm": algorithm, "hash": digest}


def verify_hash(text: str, hashed: str, algorithm: Algorithm) -> dict:
    """Verify that `text` produces `hashed` under the given algorithm."""
    if not isinstance(text, str) or text == "":
        return {"error": "text must be a non-empty string"}
    if not isinstance(hashed, str) or hashed == "":
        return {"error": "hashed must be a non-empty string"}
    if algorithm not in ("md5", "sha1", "sha256", "bcrypt"):
        return {"error": f"unsupported algorithm: {algorithm}"}

    if algorithm == "bcrypt":
        try:
            matches = bcrypt.checkpw(text.encode("utf-8"), hashed.encode("utf-8"))
        except ValueError as exc:
            return {"error": f"invalid bcrypt hash: {exc}"}
        return {"algorithm": algorithm, "matches": matches}

    computed = _DIGEST_ALGORITHMS[algorithm](text.encode("utf-8")).hexdigest()
    return {"algorithm": algorithm, "matches": computed.lower() == hashed.lower()}


if __name__ == "__main__":
    for algo in ("md5", "sha1", "sha256", "bcrypt"):
        result = hash_text("hunter2", algo)
        print(algo, "->", result)
        if "hash" in result:
            print("  verify ->", verify_hash("hunter2", result["hash"], algo))
            print("  verify wrong ->", verify_hash("wrong", result["hash"], algo))
