"""Clause REQ-2 (RFC 8725 §3.8): If a JWT contains an "iss" claim and the application expects a particular issuer, the application MUST validate the issuer.

Requirement: When an expected issuer argument is provided to decode, the function must
validate the token's "iss" claim against the expected issuer and reject the token if it
does not match.
"""

import pytest
from tinyjwt import decode, encode, InvalidTokenError

KEY = "secret-key"


def test_decode_matching_issuer_succeeds():
    claims = {"iss": "https://auth.example.com", "sub": "user123"}
    token = encode(claims, KEY)
    decoded = decode(token, KEY, issuer="https://auth.example.com")
    assert decoded["iss"] == "https://auth.example.com"
    assert decoded["sub"] == "user123"


def test_decode_mismatched_issuer_raises_invalid_token_error():
    claims = {"iss": "https://attacker.example.com", "sub": "user123"}
    token = encode(claims, KEY)
    with pytest.raises(InvalidTokenError):
        decode(token, KEY, issuer="https://auth.example.com")


def test_decode_missing_issuer_claim_raises_when_issuer_expected():
    claims = {"sub": "user123"}
    token = encode(claims, KEY)
    with pytest.raises(InvalidTokenError):
        decode(token, KEY, issuer="https://auth.example.com")


def test_decode_none_issuer_skips_issuer_validation():
    claims = {"iss": "https://auth.example.com", "sub": "user123"}
    token = encode(claims, KEY)
    decoded = decode(token, KEY, issuer=None)
    assert decoded["iss"] == "https://auth.example.com"
