from __future__ import annotations

import base64
import hashlib
import secrets


def _urlsafe(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_verifier(length_bytes: int = 64) -> str:
    """RFC 7636 code_verifier: 43..128 chars of [A-Za-z0-9-._~]. 64 random bytes -> 86 chars."""

    verifier = _urlsafe(secrets.token_bytes(length_bytes))
    if not 43 <= len(verifier) <= 128:
        raise ValueError("code_verifier length out of RFC 7636 range")
    return verifier


def code_challenge(verifier: str) -> str:
    """S256: BASE64URL(SHA256(ASCII(code_verifier))) without padding."""

    return _urlsafe(hashlib.sha256(verifier.encode("ascii")).digest())


def generate_state(length_bytes: int = 32) -> str:
    return _urlsafe(secrets.token_bytes(length_bytes))
