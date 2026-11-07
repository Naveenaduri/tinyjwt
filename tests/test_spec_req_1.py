"""Clause REQ-1 (RFC 7519 §4.1.3): Each principal intended to process the JWT MUST identify itself with a value in the audience claim.

Requirement: The decode function must require the expected audience value specified
by the caller to match a value in the JWT's 'aud' claim.
"""

import pytest
import tinyjwt
from tinyjwt import decode, encode, InvalidTokenError

# Use InvalidAudienceError if exposed, else catch base InvalidTokenError
InvalidAudienceError = getattr(tinyjwt, "InvalidAudienceError", InvalidTokenError)

KEY = "secret-key"


def test_audience_match_succeeds_for_single_and_multiple_audiences():
    """Validates that matching audience values succeed for str and list[str] aud claims."""
    # Token with single string aud matches exact caller audience
    token_single = encode({"sub": "user1", "aud": "api://service-a"}, KEY)
    claims = decode(token_single, KEY, audience="api://service-a")
    assert claims["aud"] == "api://service-a"

    # Token with list aud matches if caller audience is present in the list
    token_list = encode({"sub": "user2", "aud": ["api://service-a", "api://service-b"]}, KEY)
    claims = decode(token_list, KEY, audience="api://service-a")
    assert claims["aud"] == ["api://service-a", "api://service-b"]

    # Caller providing iterable of audiences matches if any matches token aud
    claims = decode(token_single, KEY, audience=["api://service-b", "api://service-a"])
    assert claims["aud"] == "api://service-a"

    # Token without aud succeeds when caller expects no audience (None)
    token_no_aud = encode({"sub": "user3"}, KEY)
    claims = decode(token_no_aud, KEY, audience=None)
    assert "aud" not in claims


def test_audience_mismatch_or_omission_fails():
    """Fails if expected audience does not match the token's aud claim (or presence differs)."""
    token_with_aud = encode({"sub": "user1", "aud": "api://service-a"}, KEY)
    token_no_aud = encode({"sub": "user2"}, KEY)

    # Token has aud, caller expects different audience -> must raise
    with pytest.raises(InvalidAudienceError):
        decode(token_with_aud, KEY, audience="api://other-service")

    # Exact case-sensitive match required
    with pytest.raises(InvalidAudienceError):
        decode(token_with_aud, KEY, audience="API://SERVICE-A")

    # Token has aud, caller passes audience=None -> must raise
    with pytest.raises(InvalidAudienceError):
        decode(token_with_aud, KEY, audience=None)

    # Caller specifies audience, but token has no 'aud' claim -> must raise
    with pytest.raises(InvalidAudienceError):
        decode(token_no_aud, KEY, audience="api://service-a")


def test_invalid_aud_claim_types_fail():
    """Fails when the token 'aud' claim is of an invalid type or empty."""
    # Integer aud claim
    token_int_aud = encode({"sub": "user1", "aud": 12345}, KEY)
    with pytest.raises(InvalidTokenError):
        decode(token_int_aud, KEY, audience="12345")

    # Empty list aud claim
    token_empty_aud = encode({"sub": "user2", "aud": []}, KEY)
    with pytest.raises(InvalidTokenError):
        decode(token_empty_aud, KEY, audience="api://service-a")

    # List containing non-string elements
    token_mixed_aud = encode({"sub": "user3", "aud": ["api://service-a", 123]}, KEY)
    with pytest.raises(InvalidTokenError):
        decode(token_mixed_aud, KEY, audience="api://service-a")
