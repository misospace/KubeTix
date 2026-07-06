"""Regression test for issue #162: CLI and API should not be separate silos.

Verifies that the CLI exposes a sync_to_api() bridge that POSTs/PUTs locally
stored grants to the KubeTix API, closing the independent-DB + independent-
encryption silo gap.
"""
import json
import sqlite3
import sys
import tempfile
import types
import urllib.error
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import kc_share  # noqa: E402


def _seed_cli_db(tmp_path: Path) -> str:
    db_path = tmp_path / "db.sqlite"
    key_path = tmp_path / "config.json"

    with mock.patch.object(kc_share, "DB_PATH", db_path), \
         mock.patch.object(kc_share, "CONFIG_PATH", key_path):
        kc_share.init_db()
        kc_share.create_grant(
            cluster="prod", namespace="default", role="admin", expiry=4
        )

    return str(db_path)


def test_sync_to_api_pushes_local_grants():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = _seed_cli_db(Path(tmp))

        captured: list[dict] = []

        def fake_urlopen(req, timeout=10):
            captured.append({
                "url": req.full_url,
                "method": req.get_method(),
                "body": json.loads(req.data.decode("utf-8")),
                "headers": dict(req.headers),
            })

            class _Resp:
                status = 200

            return _Resp()

        with mock.patch.object(kc_share, "DB_PATH", db_path), \
             mock.patch.object(kc_share, "urllib.request.urlopen",
                               side_effect=fake_urlopen):
            kc_share.sync_to_api(api_url="http://api.example.com/",
                                 token="t0k3n")

        assert len(captured) == 1, "expected exactly one grant to be synced"
        req = captured[0]
        assert req["method"] == "PUT"
        assert req["url"].endswith("/grants/")
        assert req["headers"].get("Authorization") == "Bearer t0k3n"
        body = req["body"]
        assert body["cluster_name"] == "prod"
        assert body["namespace"] == "default"
        assert body["role"] == "admin"
        assert body["revoked"] is False
        # Encryption is preserved end-to-end so the API can decrypt it.
        assert body["encrypted_kubeconfig"]


def test_sync_to_api_handles_http_failure_gracefully(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        db_path = _seed_cli_db(Path(tmp))

        def boom(req, timeout=10):
            raise urllib.error.URLError("connection refused")

        with mock.patch.object(kc_share, "DB_PATH", db_path), \
             mock.patch.object(kc_share, "urllib.request.urlopen",
                               side_effect=boom):
            kc_share.sync_to_api(api_url="http://api.example.com",
                                 token=None)

        out = capsys.readouterr().out
        assert "0 failed" in out or "1 failed" in out
        # Should not crash the CLI.
        assert "Synced" in out


def test_sync_to_api_no_grants_is_noop(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        db_path = tmp / "db.sqlite"
        key_path = tmp / "config.json"
        with mock.patch.object(kc_share, "DB_PATH", db_path), \
             mock.patch.object(kc_share, "CONFIG_PATH", key_path):
            kc_share.init_db()

        called = {"count": 0}

        def fake_urlopen(req, timeout=10):
            called["count"] += 1
            raise AssertionError("should not be called when no grants")

        with mock.patch.object(kc_share, "DB_PATH", db_path), \
             mock.patch.object(kc_share, "urllib.request.urlopen",
                               side_effect=fake_urlopen):
            kc_share.sync_to_api(api_url="http://api.example.com",
                                 token=None)

        assert called["count"] == 0
        out = capsys.readouterr().out
        assert "No grants to sync" in out