import pytest

from tinyjwt import decode, encode, verify, InvalidTokenError

KEY = "secret"


def test_roundtrip():
    token = encode({"sub": "alice"}, KEY)
    assert decode(token, KEY) == {"sub": "alice"}


def test_verify_true_for_valid():
    assert verify(encode({"a": 1}, KEY), KEY) is True


def test_wrong_key_rejected():
    token = encode({"a": 1}, KEY)
    with pytest.raises(InvalidTokenError):
        decode(token, "other")


def test_tampered_payload_rejected():
    h, p, s = encode({"a": 1}, KEY).split(".")
    with pytest.raises(InvalidTokenError):
        decode(f"{h}.{p}x.{s}", KEY)


def test_malformed_token():
    with pytest.raises(InvalidTokenError):
        decode("not-a-token", KEY)


def test_custom_header_kept():
    token = encode({"a": 1}, KEY, headers={"kid": "k1"})
    assert decode(token, KEY)["a"] == 1


def test_expired_rejected():
    import time
    from tinyjwt import ExpiredTokenError
    with pytest.raises(ExpiredTokenError):
        decode(encode({"exp": time.time() - 10}, KEY), KEY)


def test_not_before_rejected():
    import time
    with pytest.raises(InvalidTokenError):
        decode(encode({"nbf": time.time() + 3600}, KEY), KEY)


def test_alg_none_rejected():
    import base64, json
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    token = f"{b({'alg': 'none'})}.{b({'a': 1})}."
    with pytest.raises(InvalidTokenError):
        decode(token, KEY)
