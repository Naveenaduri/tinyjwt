"""Clause REQ-4 (RFC 7519 §4.1.3): In the special case when the JWT has one audience, the "aud" value MAY be a single case-sensitive string."""

import pytest
import tinyjwt


def test_decode_single_string_aud_exact_match():
    key = "secret-key"
    token = tinyjwt.encode({"sub": "user1", "aud": "https://api.example.com"}, key)

    payload = tinyjwt.decode(token, key, audience="https://api.example.com")
    assert payload["aud"] == "https://api.example.com"
    assert payload["sub"] == "user1"


def test_decode_single_string_aud_case_sensitive_mismatch():
    key = "secret-key"
    token = tinyjwt.encode({"sub": "user1", "aud": "MyAudience"}, key)

    # Different casing must fail validation
    with pytest.raises(tinyjwt.InvalidTokenError):
        tinyjwt.decode(token, key, audience="myaudience")


def test_decode_single_string_aud_matched_against_iterable():
    key = "secret-key"
    token = tinyjwt.encode({"sub": "user1", "aud": "service-a"}, key)

    # Caller audience can be an iterable containing the exact matching audience
    payload = tinyjwt.decode(token, key, audience=["service-b", "service-a"])
    assert payload["aud"] == "service-a"

    # Caller audience iterable with differing casing must be rejected
    with pytest.raises(tinyjwt.InvalidTokenError):
        tinyjwt.decode(token, key, audience=["service-b", "SERVICE-A"])
