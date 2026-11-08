"""Clause REQ-1 (RFC 7519 §4.1.1): The "iss" (issuer) claim identifies the principal that issued the JWT.

Conformance tests for REQ-1: decode must validate the 'iss' claim according to the API contract.
"""

import pytest
from tinyjwt import decode, encode, InvalidTokenError


KEY = "secret-key"


def test_decode_matching_issuer_succeeds():
    """When issuer is specified and matches claims['iss'], decode returns the claims."""
    claims = {"iss": "https://auth.example.com", "sub": "user123"}
    token = encode(claims, KEY)

    decoded = decode(token, KEY, issuer="https://auth.example.com")
    assert decoded == claims


def test_decode_mismatched_issuer_raises_invalid_token_error():
    """When issuer is specified but does not match claims['iss'], decode raises InvalidTokenError."""
    claims = {"iss": "https://attacker.example.com", "sub": "user123"}
    token = encode(claims, KEY)

    with pytest.raises(InvalidTokenError):
        decode(token, KEY, issuer="https://auth.example.com")


def test_decode_missing_issuer_claim_raises_invalid_token_error():
    """When issuer is specified but token lacks an 'iss' claim, decode raises InvalidTokenError."""
    claims = {"sub": "user123"}
    token = encode(claims, KEY)

    with pytest.raises(InvalidTokenError):
        decode(token, KEY, issuer="https://auth.example.com")


def test_decode_issuer_none_skips_validation():
    """When issuer is None, decode performs no issuer validation even if 'iss' is omitted or set."""
    claims_no_iss = {"sub": "user123"}
    token_no_iss = encode(claims_no_iss, KEY)
    assert decode(token_no_iss, KEY, issuer=None) == claims_no_iss

    claims_with_iss = {"iss": "https://auth.example.com", "sub": "user123"}
    token_with_iss = encode(claims_with_iss, KEY)
    assert decode(token_with_iss, KEY, issuer=None) == claims_with_iss
    assert decode(token_with_iss, KEY) == claims_with_iss
