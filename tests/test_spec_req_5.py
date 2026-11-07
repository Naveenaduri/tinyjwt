"""Clause REQ-5 (RFC 8725 §3.9): the JWT MUST contain an "aud" claim, and the relying party MUST validate it.

Tests for REQ-5 audience validation conformance during token decode.
"""
import pytest
from tinyjwt import decode, encode, InvalidTokenError

try:
    from tinyjwt import InvalidAudienceError
except ImportError:
    InvalidAudienceError = InvalidTokenError


KEY = "secret-key-123"


def test_audience_validation_success():
    # Successful validation when audience matches string or list of audiences
    token_str = encode({"sub": "user1", "aud": "https://api.example.com"}, KEY)
    claims = decode(token_str, KEY, audience="https://api.example.com")
    assert claims["aud"] == "https://api.example.com"

    token_list = encode({"sub": "user2", "aud": ["aud1", "aud2"]}, KEY)
    claims = decode(token_list, KEY, audience="aud1")
    assert claims["aud"] == ["aud1", "aud2"]

    claims = decode(token_list, KEY, audience=["aud2", "aud3"])
    assert claims["aud"] == ["aud1", "aud2"]


def test_audience_missing_when_expected_raises():
    # When audience validation is requested, token MUST contain 'aud' claim
    token = encode({"sub": "user1"}, KEY)
    with pytest.raises(InvalidAudienceError):
        decode(token, KEY, audience="https://api.example.com")


def test_audience_mismatch_or_unexpected_raises():
    # Token has 'aud' but caller expects a different audience -> must raise
    token = encode({"sub": "user1", "aud": "https://client.example.com"}, KEY)
    with pytest.raises(InvalidAudienceError):
        decode(token, KEY, audience="https://api.example.com")

    # Token has 'aud' but caller passes audience=None -> must raise
    with pytest.raises(InvalidAudienceError):
        decode(token, KEY, audience=None)


def test_audience_malformed_claim_type_raises():
    # 'aud' claim must be str or list of non-empty str, any other type must raise InvalidTokenError
    token_int_aud = encode({"sub": "user1", "aud": 12345}, KEY)
    with pytest.raises(InvalidTokenError):
        decode(token_int_aud, KEY, audience="12345")

    token_empty_list_aud = encode({"sub": "user1", "aud": []}, KEY)
    with pytest.raises(InvalidTokenError):
        decode(token_empty_list_aud, KEY, audience="aud1")
