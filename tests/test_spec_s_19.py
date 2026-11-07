"""Clause S-19 (RFC 8725 Signature comparison (timing)): Signature comparison SHOULD use a constant-time comparison to avoid timing side channels."""

import hmac
from unittest.mock import patch
import pytest
from tinyjwt import decode, encode, verify


def test_verify_uses_constant_time_comparison():
    """Verify that signature comparison invokes hmac.compare_digest."""
    key = "secret-key"
    token = encode({"sub": "user123"}, key)

    with patch("hmac.compare_digest", wraps=hmac.compare_digest) as mock_compare:
        valid = verify(token, key)
        assert valid is True
        assert mock_compare.called, "verify() must use a constant-time comparison function (hmac.compare_digest)"


def test_decode_uses_constant_time_comparison():
    """Verify that token decoding and signature check invokes hmac.compare_digest."""
    key = "secret-key"
    token = encode({"sub": "user123"}, key)

    with patch("hmac.compare_digest", wraps=hmac.compare_digest) as mock_compare:
        claims = decode(token, key)
        assert claims["sub"] == "user123"
        assert mock_compare.called, "decode() must use a constant-time comparison function (hmac.compare_digest)"
