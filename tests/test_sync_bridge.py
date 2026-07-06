"""Regression test for issue #162: CLI and API should not be separate silos.

Verifies that the CLI exposes a sync_to_api() bridge that POSTs/PUTs locally
stored grants to the KubeTix API, closing the independent-DB + independent-
encryption silo gap.
"""

import importlib.util
import json
import sqlite3
import sys
import tempfile
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]

# Import kc-share.py (hyphenated module name requires importlib)
spec = importlib.util.spec_from_file_location(
    "kc_share",
    REPO_ROOT / "kc-share.py",
)
kc_share = importlib.util.module_from_spec(spec)
sys.modules["kc_share"] = kc_share
spec.loader.exec_module(kc_share)


def _seed_cli_db(db_path):
    """Create a temporary CLI DB with one grant row."""
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS grants (
            id TEXT PRIMARY KEY,
            cluster_name TEXT NOT NULL,
            namespace TEXT,
            role TEXT NOT NULL,
            created_at TEXT,
            expires_at TEXT,
            revoked INTEGER DEFAULT 0,
            metadata TEXT,
            encrypted_kubeconfig TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            grant_id TEXT NOT NULL,
            action TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )
    """)
    cursor.execute(
        """
        INSERT INTO grants (id, cluster_name, namespace, role, created_at,
                            expires_at, revoked, metadata, encrypted_kubeconfig)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        ("g-1", "test-cluster", "default", "view", None, None, 0, None, "enc"),
    )
    conn.commit()
    conn.close()
    return db_path


class _MockHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that records the request."""

    received = None

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _MockHandler.received = {
            "path": self.path,
            "body": json.loads(body),
        }
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"synced": 1}).encode())

    def log_message(self, format, *args):
        pass  # silence stderr


def _start_server(port=18099):
    server = HTTPServer(("127.0.0.1", port), _MockHandler)
    t = Thread(target=server.handle_request, daemon=True)
    t.start()
    return server


def test_sync_to_api_pushes_local_grants(tmp_path):
    """sync_to_api should PUT each active grant to the API."""
    db_path = _seed_cli_db(str(tmp_path / "test.db"))

    # Patch DB_PATH so get_connection uses our temp DB
    with mock.patch.object(kc_share, "DB_PATH", Path(db_path)):
        port = 18099
        server = _start_server(port)
        try:
            kc_share.sync_to_api(
                api_url=f"http://127.0.0.1:{port}",
                token=None,
            )
        finally:
            server.server_close()

        assert _MockHandler.received is not None
        assert "/grants/g-1" in _MockHandler.received["path"]
        payload = _MockHandler.received["body"]
        assert payload["id"] == "g-1"
        assert payload["cluster_name"] == "test-cluster"


def test_sync_to_api_no_grants(tmp_path):
    """sync_to_api should print 'No grants to sync' when DB is empty."""
    db_path = str(tmp_path / "empty.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS grants (
            id TEXT PRIMARY KEY,
            cluster_name TEXT NOT NULL,
            namespace TEXT,
            role TEXT NOT NULL,
            created_at TEXT,
            expires_at TEXT,
            revoked INTEGER DEFAULT 0,
            metadata TEXT,
            encrypted_kubeconfig TEXT
        )
    """)
    conn.commit()
    conn.close()

    with mock.patch.object(kc_share, "DB_PATH", Path(db_path)):
        captured = []

        class _CapturePrint:
            def write(self, s):
                captured.append(s)

            def flush(self):
                pass

        with mock.patch("sys.stdout", _CapturePrint()):
            kc_share.sync_to_api(
                api_url="http://127.0.0.1:18099",
                token=None,
            )

        assert any("No grants to sync" in s for s in captured)


def test_sync_to_api_skips_revoked(tmp_path):
    """sync_to_api should skip revoked grants."""
    db_path = _seed_cli_db(str(tmp_path / "test.db"))
    # Mark the grant as revoked
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE grants SET revoked = 1 WHERE id = 'g-1'")
    conn.commit()
    conn.close()

    with mock.patch.object(kc_share, "DB_PATH", Path(db_path)):
        captured = []

        class _CapturePrint:
            def write(self, s):
                captured.append(s)

            def flush(self):
                pass

        with mock.patch("sys.stdout", _CapturePrint()):
            kc_share.sync_to_api(
                api_url="http://127.0.0.1:18099",
                token=None,
            )

        assert any("No grants to sync" in s for s in captured)


def test_sync_to_api_handles_failure(tmp_path):
    """sync_to_api should handle HTTP errors gracefully."""
    db_path = _seed_cli_db(str(tmp_path / "test.db"))

    with mock.patch.object(kc_share, "DB_PATH", Path(db_path)):
        captured = []

        class _CapturePrint:
            def write(self, s):
                captured.append(s)

            def flush(self):
                pass

        with mock.patch("sys.stdout", _CapturePrint()):
            # Point to a non-existent server so the request fails
            kc_share.sync_to_api(
                api_url="http://127.0.0.1:19999",
                token=None,
            )

        output = "".join(captured)
        assert "failed" in output.lower()


def test_sync_subcommand_registered():
    """The CLI should expose a 'sync' subcommand."""
    import subprocess

    result = subprocess.run(
        ["python", str(REPO_ROOT / "kc-share.py"), "--help"],
        capture_output=True,
        text=True,
    )
    assert "sync" in result.stdout


def test_sync_to_api_sends_auth_token():
    """sync_to_api should include Authorization header when token is provided."""
    received_headers = {}

    class _AuthHandler(BaseHTTPRequestHandler):
        def do_PUT(self):
            received_headers["Authorization"] = self.headers.get("Authorization")
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"synced": 1}).encode())

        def log_message(self, format, *args):
            pass

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    _seed_cli_db(db_path)

    port = 18098
    server = HTTPServer(("127.0.0.1", port), _AuthHandler)
    t = Thread(target=server.handle_request, daemon=True)
    t.start()

    try:
        with mock.patch.object(kc_share, "DB_PATH", Path(db_path)):
            kc_share.sync_to_api(
                api_url=f"http://127.0.0.1:{port}",
                token="test-token-123",
            )
    finally:
        server.server_close()

    assert received_headers.get("Authorization") == "Bearer test-token-123"


def test_sync_to_api_writes_audit_log(tmp_path):
    """sync_to_api should write audit_log entries for synced grants."""
    db_path = _seed_cli_db(str(tmp_path / "test.db"))

    port = 18097
    server = HTTPServer(("127.0.0.1", port), _MockHandler)
    t = Thread(target=server.handle_request, daemon=True)
    t.start()

    try:
        with mock.patch.object(kc_share, "DB_PATH", Path(db_path)):
            kc_share.sync_to_api(
                api_url=f"http://127.0.0.1:{port}",
                token=None,
            )
    finally:
        server.server_close()

    # Verify audit_log entry was created
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute(
        "SELECT grant_id, action FROM audit_log WHERE action = 'synced_to_api'"
    )
    rows = cursor.fetchall()
    conn.close()

    assert len(rows) == 1
    assert rows[0][0] == "g-1"
    assert rows[0][1] == "synced_to_api"
