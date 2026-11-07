"""Clause REQ-2 (RFC 7519 §4.1.3): If the principal processing the claim does not identify itself with a value in the "aud" claim when this claim is present, then the JWT MUST be rejected.

Conformance tests for REQ-2 audience claim validation.
"""

import pytest

import tinyjwt
from tinyjwt import decode, encode

SECRET = "test-secret-key"


def test_reject_when_aud_present_and_no_audience_specified():
    """If 'aud' is in claims and caller provides audience=None, reject."""
    token = encode({"sub": "user1", "aud": "https://api.example.com"}, SECRET)
    error_type = getattr(tinyjwt, "InvalidAudienceError", tinyjwt.InvalidTokenError)
    with pytest.raises(error_type):
        decode(token, SECRET, audience=None)


def test_reject_when_aud_does_not_match_expected_audience():
    """If 'aud' is present but does not match caller audience, reject."""
    token = encode({"sub": "user1", "aud": "https://api.example.com"}, SECRET)
    error_type = getattr(tinyjwt, "InvalidAudienceError", tinyjwt.InvalidTokenError)
    with pytest.raises(error_type):
        decode(token, SECRET, audience="https://other.example.com")


def test_reject_when_aud_case_mismatch():
    """Audience comparison must be an exact case-sensitive match."""
    token = encode({"sub": "user1", "aud": "https://api.example.com/Audience"}, SECRET)
    error_type = getattr(tinyjwt, "InvalidAudienceError", tinyjwt.InvalidTokenError)
    with pytest.raises(error_type):
        decode(token, SECRET, audience="https://api.example.com/audience")


def test_accept_when_aud_matches_expected_audience():
    """Accept when caller identifies itself with the value in 'aud' claim (string and list forms)."""
    token_single = encode({"sub": "user1", "aud": "client_a"}, SECRET)
    claims_single = decode(token_single, SECRET, audience="client_a")
    assert claims_single["aud"] == "client_a"

    token_list = encode({"sub": "user2", "aud": ["client_a", "client_b"]}, SECRET)
    claims_list = decode(token_list, SECRET, audience="client_b")
    assert claims_list["aud"] == ["client_a", "client_b"]
