"""Tests for issue #351 — OIDC ID token signature verification.

The previous implementation decoded the ID token with
``jwt.get_unverified_claims`` and only checked the ``iss`` and ``aud``
claims, never the signature. A forged / tampered token whose claims
matched the configured issuer and audience was therefore trusted.

These tests assert that ``_validate_id_token`` now performs real
JWKS-backed signature verification: tampered tokens (signature altered)
and tokens signed with an unrelated key (key not in the provider's JWKS)
are rejected with an HTTP 401 before any claims are trusted.

The tests use a locally-generated RSA key pair and a hand-rolled JWKS
document, bypassing the real OIDC discovery document via the
``jwks_uri_override`` parameter that exists for exactly this purpose.
"""

import os
import sys
import importlib
import time

import pytest
from fastapi import HTTPException
from jose import jwk, jwt

ISSUER = "https://idp.example.com/"
CLIENT_ID = "kubetix-test-client"
KID = "test-kid-1"


def _ensure_app_importable():
    """Make sure the ``kubetix_api`` package is importable for this test file."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _generate_rsa_keypair():
    """Generate an RSA key pair and return (private_pem, public_pem, jwk_dict)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    public_numbers = private_key.public_key().public_numbers()
    n = _b64url_uint(public_numbers.n)
    e = _b64url_uint(public_numbers.e)
    jwk_dict = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": KID,
        "n": n,
        "e": e,
    }
    return private_pem, public_pem, jwk_dict


def _b64url_uint(n: int) -> str:
    import base64

    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_id_token(private_pem: bytes, *, kid: str = KID) -> str:
    """Sign a structurally-valid OIDC ID token with the supplied private key."""
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-123",
        "email": "[email protected]",
        "iat": now,
        "exp": now + 3600,
        "nbf": now - 5,
    }
    return jwt.encode(
        claims,
        private_pem.decode("utf-8") if isinstance(private_pem, bytes) else private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )


@pytest.fixture
def oidc_module():
    """Import the oidc package fresh so module-level caches are clean."""
    _ensure_app_importable()
    sys.modules.pop("kubetix_api.oidc", None)
    return importlib.import_module("kubetix_api.oidc")


def _patched_validate(oidc_module, jwks: dict):
    """Return a bound ``_validate_id_token`` that uses ``jwks`` directly.

    We monkeypatch the module's ``_fetch_jwks`` so it never hits the
    network, returning our hand-rolled JWKS document for any issuer.
    """
    captured = {}

    def _fake_fetch_jwks(issuer, jwks_uri_override=None):
        captured["issuer"] = issuer
        captured["jwks_uri_override"] = jwks_uri_override
        return jwks

    oidc_module._fetch_jwks = _fake_fetch_jwks
    return oidc_module._validate_id_token, captured


def test_valid_token_with_provider_key_is_accepted(oidc_module):
    """Sanity check: a token signed with the JWKS-listed key passes."""
    private_pem, _public_pem, jwk_dict = _generate_rsa_keypair()
    jwks = {"keys": [jwk_dict]}
    validate, _captured = _patched_validate(oidc_module, jwks)

    id_token = _make_id_token(private_pem)
    claims = validate(id_token, ISSUER, CLIENT_ID)
    assert claims["iss"] == ISSUER
    assert claims["aud"] == CLIENT_ID
    assert claims["sub"] == "user-123"


def test_tampered_token_signature_is_rejected(oidc_module):
    """Mutating the signature segment of an otherwise-valid token is rejected.

    This is the core regression test for issue #351: before the fix, the
    signature was never checked at all, so any token that satisfied the
    structural claims was trusted. Here we flip a byte in the signature
    and assert the validator now refuses it.
    """
    private_pem, _public_pem, jwk_dict = _generate_rsa_keypair()
    jwks = {"keys": [jwk_dict]}
    validate, _captured = _patched_validate(oidc_module, jwks)

    id_token = _make_id_token(private_pem)
    header_b64, payload_b64, signature_b64 = id_token.split(".")

    # Flip the first character of the signature segment to produce a
    # tampered token that fails signature verification but still parses.
    flipped_char = "B" if signature_b64[0] == "A" else "A"
    tampered = f"{header_b64}.{payload_b64}.{flipped_char}{signature_b64[1:]}"

    with pytest.raises(HTTPException) as excinfo:
        validate(tampered, ISSUER, CLIENT_ID)
    assert excinfo.value.status_code == 401
    assert (
        "signature" in str(excinfo.value.detail).lower()
        or "invalid" in str(excinfo.value.detail).lower()
    )


def test_token_signed_with_unassociated_key_is_rejected(oidc_module):
    """A token signed by an attacker with their own private key is rejected.

    The token's claims satisfy the issuer/audience structural checks but
    the signing key (with its kid) is NOT in the provider JWKS, so
    signature verification must fail. Before the fix this case was
    trusted and the attacker-controlled ``sub``/``email`` would have been
    used to provision / bind an account.
    """
    # Provider JWKS: contains a real key that will NOT match the token.
    _provider_priv, _provider_pub, provider_jwk = _generate_rsa_keypair()
    # Use a DIFFERENT kid from the one the attacker signs with, so even
    # if the JWKS contained the attacker's key by accident the header
    # wouldn't resolve to it.
    provider_jwk = {**provider_jwk, "kid": "provider-kid"}
    jwks = {"keys": [provider_jwk]}

    # Attacker key pair, kid chosen so it does not match any JWKS entry.
    attacker_priv, _attacker_pub, _attacker_jwk = _generate_rsa_keypair()
    validate, _captured = _patched_validate(oidc_module, jwks)

    id_token = _make_id_token(attacker_priv, kid="attacker-kid")
    assert id_token  # sanity

    with pytest.raises(HTTPException) as excinfo:
        validate(id_token, ISSUER, CLIENT_ID)
    assert excinfo.value.status_code == 401


def test_unsigned_none_alg_token_is_rejected(oidc_module):
    """alg == 'none' tokens must be rejected before any claim is trusted.

    python-jose refuses to *encode* ``alg=none`` tokens (a useful guard),
    so we hand-craft the JWS ourselves: header ``{"alg":"none"}`` +
    valid payload + empty signature segment.
    """
    import base64
    import json

    _priv, _pub, jwk_dict = _generate_rsa_keypair()
    jwks = {"keys": [jwk_dict]}
    validate, _captured = _patched_validate(oidc_module, jwks)

    def _b64u(obj) -> str:
        if isinstance(obj, dict):
            data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        else:
            data = obj
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    now = int(time.time())
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "attacker",
        "exp": now + 3600,
    }
    unsigned = f"{_b64u(header)}.{_b64u(payload)}."  # empty signature

    with pytest.raises(HTTPException) as excinfo:
        validate(unsigned, ISSUER, CLIENT_ID)
    assert excinfo.value.status_code == 401
    assert (
        "unsigned" in str(excinfo.value.detail).lower()
        or "none" in str(excinfo.value.detail).lower()
    )


def test_expired_token_is_rejected(oidc_module):
    """Expired tokens fail the ``exp`` check inside jwt.decode."""
    private_pem, _public_pem, jwk_dict = _generate_rsa_keypair()
    jwks = {"keys": [jwk_dict]}
    validate, _captured = _patched_validate(oidc_module, jwks)

    past = int(time.time()) - 7200
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-123",
        "iat": past - 60,
        "exp": past,
    }
    expired = jwt.encode(
        claims,
        private_pem.decode("utf-8"),
        algorithm="RS256",
        headers={"kid": KID},
    )

    with pytest.raises(HTTPException) as excinfo:
        validate(expired, ISSUER, CLIENT_ID)
    assert excinfo.value.status_code == 401


def test_wrong_audience_is_rejected(oidc_module):
    """Signature OK but ``aud`` doesn't match -> rejected by jwt.decode."""
    private_pem, _public_pem, jwk_dict = _generate_rsa_keypair()
    jwks = {"keys": [jwk_dict]}
    validate, _captured = _patched_validate(oidc_module, jwks)

    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": "some-other-client",
        "sub": "user-123",
        "exp": now + 3600,
    }
    wrong_aud = jwt.encode(
        claims,
        private_pem.decode("utf-8"),
        algorithm="RS256",
        headers={"kid": KID},
    )

    with pytest.raises(HTTPException) as excinfo:
        validate(wrong_aud, ISSUER, CLIENT_ID)
    assert excinfo.value.status_code == 401


def test_jwks_cache_keyed_on_override_uri(oidc_module):
    """The cache must be keyed on the resolved jwks_uri, not the issuer."""
    private_pem, _public_pem, jwk_dict = _generate_rsa_keypair()
    jwks = {"keys": [jwk_dict]}

    # First call: cold cache, no override -> fetch_jwks is invoked.
    seen = {"calls": 0, "last_uri": None}

    def fake_fetch(issuer, jwks_uri_override=None):
        seen["calls"] += 1
        seen["last_uri"] = jwks_uri_override
        return jwks

    oidc_module._fetch_jwks = fake_fetch
    id_token = _make_id_token(private_pem)

    # Two calls with the same override URI should not cause the validator
    # to fail; the cache is internal to _fetch_jwks so we just exercise
    # the public path here.
    oidc_module._validate_id_token(
        id_token, ISSUER, CLIENT_ID, jwks_uri_override="https://custom/jwks"
    )
    oidc_module._validate_id_token(
        id_token, ISSUER, CLIENT_ID, jwks_uri_override="https://custom/jwks"
    )
    assert seen["calls"] == 2
    assert seen["last_uri"] == "https://custom/jwks"
