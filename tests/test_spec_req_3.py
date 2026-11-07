"""Clause REQ-3 (RFC 7519 §4.1.3): In the general case, the "aud" value is an array of case-sensitive strings, each containing a StringOrURI value.

Conformance tests verifying that decode supports validating an 'aud' claim
formatted as an array of strings using case-sensitive comparison.
"""

import pytest
from tinyjwt import decode, encode, InvalidTokenError

try:
    from tinyjwt import InvalidAudienceError
except ImportError:
    InvalidAudienceError = InvalidTokenError


KEY = "secret-key"


def test_aud_array_matches_single_audience():
    claims = {"sub": "1234567890", "aud": ["client-app", "admin-api"]}
    token = encode(claims, KEY)

    decoded = decode(token, KEY, audience="client-app")
    assert decoded["aud"] == ["client-app", "admin-api"]

    decoded_other = decode(token, KEY, audience="admin-api")
    assert decoded_other["aud"] == ["client-app", "admin-api"]


def test_aud_array_matches_iterable_audience():
    claims = {"sub": "1234567890", "aud": ["service-a", "service-b"]}
    token = encode(claims, KEY)

    decoded = decode(token, KEY, audience=["service-b", "service-c"])
    assert decoded["aud"] == ["service-a", "service-b"]


def test_aud_array_case_sensitive_mismatch():
    claims = {"sub": "1234567890", "aud": ["Client-App", "admin-api"]}
    token = encode(claims, KEY)

    with pytest.raises(InvalidAudienceError):
        decode(token, KEY, audience="client-app")

    with pytest.raises(InvalidAudienceError):
        decode(token, KEY, audience=["client-app", "ADMIN-API"])


def test_aud_array_missing_audience_match():
    claims = {"sub": "1234567890", "aud": ["service-a", "service-b"]}
    token = encode(claims, KEY)

    with pytest.raises(InvalidAudienceError):
        decode(token, KEY, audience="service-c")

    with pytest.raises(InvalidAudienceError):
        decode(token, KEY, audience=["service-x", "service-y"])
