"""Core encode/decode/verify for HS256 JWTs (RFC 7519 / RFC 7515)."""
import base64
from collections.abc import Iterable
import hashlib
import hmac
import json
import time


class InvalidTokenError(Exception):
    """Raised when a token is malformed or fails validation."""


class ExpiredTokenError(InvalidTokenError):
    """Raised when a token's exp claim is in the past."""


class InvalidAudienceError(InvalidTokenError):
    """Raised when a token's aud claim is missing, malformed, or does not match."""


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:  # noqa: BLE001
        raise InvalidTokenError("bad base64") from exc


def _sign(signing_input: bytes, key: bytes) -> bytes:
    return hmac.new(key, signing_input, hashlib.sha256).digest()


def encode(claims: dict, key: str, headers: dict | None = None) -> str:
    """Encode claims into a signed HS256 token."""
    header = {"alg": "HS256", "typ": "JWT"}
    if headers:
        header.update(headers)
    h = _b64e(json.dumps(header, separators=(",", ":")).encode())
    p = _b64e(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64e(_sign(f"{h}.{p}".encode(), key.encode()))
    return f"{h}.{p}.{sig}"


def _split(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidTokenError("token must have three segments")
    return parts


def verify(token: str, key: str) -> bool:
    """Return True if the token's signature is valid for key."""
    h, p, s = _split(token)
    try:
        header = json.loads(_b64d(h))
    except ValueError as exc:
        raise InvalidTokenError("bad header") from exc
    alg = header.get("alg")
    if alg != "HS256":
        raise InvalidTokenError(f"unsupported alg {alg!r}")
    expected = _b64e(_sign(f"{h}.{p}".encode(), key.encode()))
    return expected == s


def _validate_aud(claims: dict, audience: str | Iterable[str] | None) -> None:
    if "aud" not in claims:
        if audience is not None:
            raise InvalidAudienceError("missing audience claim")
        return

    token_aud = claims["aud"]
    if isinstance(token_aud, str):
        if not token_aud:
            raise InvalidAudienceError("invalid audience claim")
        token_audiences = [token_aud]
    elif isinstance(token_aud, list):
        if not token_aud or not all(isinstance(a, str) and a for a in token_aud):
            raise InvalidAudienceError("invalid audience claim")
        token_audiences = token_aud
    else:
        raise InvalidAudienceError("invalid audience claim")

    if audience is None:
        raise InvalidAudienceError("unexpected audience claim")

    if isinstance(audience, str):
        if not audience:
            raise InvalidAudienceError("invalid expected audience")
        expected_audiences = [audience]
    elif isinstance(audience, Iterable) and not isinstance(audience, (bytes, dict)):
        expected_audiences = list(audience)
        if not expected_audiences or not all(isinstance(a, str) and a for a in expected_audiences):
            raise InvalidAudienceError("invalid expected audience")
    else:
        raise InvalidAudienceError("invalid expected audience")

    if not any(aud in token_audiences for aud in expected_audiences):
        raise InvalidAudienceError("audience mismatch")


def decode(token: str, key: str, audience: str | Iterable[str] | None = None) -> dict:
    """Verify a token and return its claims."""
    if not verify(token, key):
        raise InvalidTokenError("signature verification failed")
    _, p, _ = _split(token)
    try:
        claims = json.loads(_b64d(p))
    except ValueError as exc:
        raise InvalidTokenError("bad payload") from exc
    if not isinstance(claims, dict):
        raise InvalidTokenError("payload must be a JSON object")
    now = time.time()
    if "exp" in claims and now >= claims["exp"]:
        raise ExpiredTokenError("token expired")
    if "nbf" in claims and now < claims["nbf"]:
        raise InvalidTokenError("token not yet valid")
    _validate_aud(claims, audience)
    return claims
