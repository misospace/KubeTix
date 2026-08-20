"""Tests for issue #353: KUBECONFIG_ENCRYPTION_KEY missing should surface a clear 503.

When the encryption key is absent, grant creation and download must return a
clear 503 with an actionable message rather than an unhandled 500. These tests
exercise the ``_encryption_key_error_response`` helper and the
``create_grant`` / ``get_grant`` error-handling wrappers around
``_get_fernet()``.
"""

import importlib
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException


def _import_grants_module(monkeypatch, key_value=None):
    """Import the grants module with a controlled KUBECONFIG_ENCRYPTION_KEY."""
    if key_value is None:
        monkeypatch.delenv("KUBECONFIG_ENCRYPTION_KEY", raising=False)
    else:
        monkeypatch.setenv("KUBECONFIG_ENCRYPTION_KEY", key_value)

    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    sys.modules.pop("kubetix_api.grants", None)
    return importlib.import_module("kubetix_api.grants")


def test_get_fernet_missing_key_raises_value_error(monkeypatch):
    """A missing KUBECONFIG_ENCRYPTION_KEY raises a clear ValueError."""
    grants = _import_grants_module(monkeypatch, key_value=None)

    with pytest.raises(ValueError) as exc_info:
        grants._get_fernet()

    assert "KUBECONFIG_ENCRYPTION_KEY" in str(exc_info.value)


def test_encryption_key_error_response_returns_503(monkeypatch):
    """The helper returns an HTTP 503 — not a 500 — when the key is missing."""
    grants = _import_grants_module(monkeypatch, key_value=None)

    exc = grants._encryption_key_error_response(
        ValueError("KUBECONFIG_ENCRYPTION_KEY must be set")
    )

    assert isinstance(exc, HTTPException)
    assert exc.status_code == 503
    assert "KUBECONFIG_ENCRYPTION_KEY" in exc.detail
    # The message must be actionable: how to fix it.
    assert "Fernet" in exc.detail or "cryptography" in exc.detail


def test_get_fernet_with_valid_key_returns_fernet(monkeypatch):
    """A valid Fernet key produces a working Fernet instance."""
    from cryptography.fernet import Fernet

    valid_key = Fernet.generate_key().decode()
    grants = _import_grants_module(monkeypatch, key_value=valid_key)

    fernet = grants._get_fernet()
    assert isinstance(fernet, Fernet)

    # Round-trip sanity check: encryption then decryption returns the original.
    blob = fernet.encrypt(b"hello")
    assert fernet.decrypt(blob) == b"hello"
