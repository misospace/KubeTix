#!/usr/bin/env python3
"""
KubeContext Manager - CLI Tool
Generate and manage temporary Kubernetes access
"""

import argparse
import json
import os
import secrets
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("Installing cryptography...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.fernet import Fernet

# Configuration
DB_PATH = Path.home() / ".kc-share" / "db.sqlite"
CONFIG_PATH = Path.home() / ".kc-share" / "config.json"
ENCRYPTION_KEY = os.environ.get("KC_SHARE_KEY") or None


def init_db():
    """Initialize the database"""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Track schema version for migrations
    SCHEMA_VERSION = 2

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create schema_version table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS grants (
            id TEXT PRIMARY KEY,
            cluster_name TEXT NOT NULL,
            namespace TEXT,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            revoked BOOLEAN DEFAULT 0,
            metadata TEXT,
            encrypted_kubeconfig TEXT
        )
    """)

    # Check if we need to add encrypted_kubeconfig column (migration from v1)
    cursor.execute("SELECT version FROM schema_version LIMIT 1")
    row = cursor.fetchone()
    current_version = row[0] if row else 0

    if current_version < SCHEMA_VERSION:
        # Check if encrypted_kubeconfig column already exists (partial migration)
        cursor.execute("PRAGMA table_info(grants)")
        columns = [col[1] for col in cursor.fetchall()]

        if "encrypted_kubeconfig" not in columns:
            cursor.execute("""
                ALTER TABLE grants ADD COLUMN encrypted_kubeconfig TEXT
            """)

        # Ensure audit_log has created_at column (API uses created_at)
        cursor.execute("PRAGMA table_info(audit_log)")
        audit_columns = [col[1] for col in cursor.fetchall()]
        if "created_at" not in audit_columns and "timestamp" in audit_columns:
            # Rename timestamp to created_at via migration
            cursor.execute("""
                CREATE TABLE audit_log_new (
                    id TEXT PRIMARY KEY,
                    grant_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            """)
            cursor.execute(
                "INSERT INTO audit_log_new (id, grant_id, action, created_at, details) "
                "SELECT id, grant_id, action, timestamp, details FROM audit_log"
            )
            cursor.execute("DROP TABLE audit_log")
            cursor.execute("ALTER TABLE audit_log_new RENAME TO audit_log")

        # Migrate existing grants: move encrypted kubeconfig from metadata to new column
        cursor.execute(
            "SELECT id, metadata FROM grants WHERE metadata IS NOT NULL AND encrypted_kubeconfig IS NULL"
        )
        for row in cursor.fetchall():
            grant_id, metadata_str = row
            if metadata_str:
                try:
                    metadata = json.loads(metadata_str)
                    if "kubeconfig_encrypted" in metadata:
                        # Decrypt and re-encrypt with current key (key may have changed)
                        encrypted_kubeconfig = encrypt_data(
                            decrypt_data(metadata["kubeconfig_encrypted"])
                        )
                        cursor.execute(
                            "UPDATE grants SET encrypted_kubeconfig = ? WHERE id = ?",
                            (encrypted_kubeconfig, grant_id),
                        )
                except (json.JSONDecodeError, Exception):
                    pass  # Skip malformed metadata

        cursor.execute("DELETE FROM schema_version")
        cursor.execute("INSERT INTO schema_version VALUES (?)", (SCHEMA_VERSION,))
        conn.commit()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            grant_id TEXT NOT NULL,
            action TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )
    """)

    conn.commit()
    conn.close()


def get_connection():
    """Get database connection"""
    init_db()
    return sqlite3.connect(DB_PATH)


def get_encryption_key() -> str:
    """Generate or retrieve encryption key"""
    global ENCRYPTION_KEY

    if ENCRYPTION_KEY:
        return ENCRYPTION_KEY

    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            config = json.load(f)
            ENCRYPTION_KEY = config.get("encryption_key")
            if ENCRYPTION_KEY:
                return ENCRYPTION_KEY

    ENCRYPTION_KEY = Fernet.generate_key().decode()

    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump({"encryption_key": ENCRYPTION_KEY}, f)

    return ENCRYPTION_KEY


def encrypt_data(data: str) -> str:
    """Encrypt data"""
    key = get_encryption_key()
    f = Fernet(key.encode())
    return f.encrypt(data.encode()).decode()


def decrypt_data(encrypted: str) -> str:
    """Decrypt data"""
    key = get_encryption_key()
    f = Fernet(key.encode())
    return f.decrypt(encrypted.encode()).decode()


def create_grant(
    cluster_name: str, namespace: Optional[str], role: str, expiry_hours: int
) -> str:
    """Create a new access grant"""
    conn = get_connection()
    cursor = conn.cursor()

    grant_id = secrets.token_urlsafe(16)
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(hours=expiry_hours)

    # Get kubeconfig
    kubeconfig_path = os.environ.get("KUBECONFIG", Path.home() / ".kube" / "config")

    if not os.path.exists(kubeconfig_path):
        raise FileNotFoundError(f"Kubeconfig not found at {kubeconfig_path}")

    with open(kubeconfig_path) as f:
        kubeconfig = f.read()

    # Encrypt and store directly (unified with API schema)
    encrypted_kubeconfig = encrypt_data(kubeconfig)

    cursor.execute(
        """
        INSERT INTO grants (id, cluster_name, namespace, role, expires_at,
                            encrypted_kubeconfig)
        VALUES (?, ?, ?, ?, ?, ?)
    """,
        (
            grant_id,
            cluster_name,
            namespace,
            role,
            expires_at.isoformat(),
            encrypted_kubeconfig,
        ),
    )

    cursor.execute(
        """
        INSERT INTO audit_log (id, grant_id, action, details)
        VALUES (?, ?, ?, ?)
    """,
        (
            secrets.token_urlsafe(8),
            grant_id,
            "created",
            f"Created grant for {cluster_name}",
        ),
    )

    conn.commit()
    conn.close()

    return grant_id


def get_grant(grant_id: str) -> Optional[dict]:
    """Retrieve a grant by ID"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM grants WHERE id = ?", (grant_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return None

    # Determine column layout dynamically to support both old and new schemas
    cursor.execute("PRAGMA table_info(grants)")
    columns = {col[1]: idx for idx, col in enumerate(cursor.fetchall())}
    conn.close()

    encrypted_kc = None
    if "encrypted_kubeconfig" in columns:
        encrypted_kc = row[columns["encrypted_kubeconfig"]] or None
    elif "metadata" in columns:
        # Legacy: try to decrypt kubeconfig from metadata
        meta_str = row[columns.get("metadata", 7)] or ""
        try:
            meta = json.loads(meta_str)
            if "kubeconfig_encrypted" in meta:
                encrypted_kc = meta["kubeconfig_encrypted"]
        except (json.JSONDecodeError, KeyError):
            pass

    return {
        "id": row[columns.get("id", 0)],
        "cluster_name": row[columns.get("cluster_name", 1)],
        "namespace": row[columns.get("namespace", 2)],
        "role": row[columns.get("role", 3)],
        "created_at": row[columns.get("created_at", 4)],
        "expires_at": row[columns.get("expires_at", 5)],
        "revoked": bool(row[columns.get("revoked", 6)]),
        "encrypted_kubeconfig": encrypted_kc,
    }


def list_grants() -> list:
    """List all active grants"""
    conn = get_connection()
    cursor = conn.cursor()

    # Use ISO format comparison for timezone-aware timestamps
    now_utc = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        """
        SELECT id, cluster_name, namespace, role, created_at, expires_at, revoked
        FROM grants
        WHERE revoked = 0 AND expires_at > ?
        ORDER BY created_at DESC
    """,
        (now_utc,),
    )

    grants = []
    for row in cursor.fetchall():
        grants.append(
            {
                "id": row[0],
                "cluster_name": row[1],
                "namespace": row[2],
                "role": row[3],
                "created_at": row[4],
                "expires_at": row[5],
                "revoked": bool(row[6]),
            }
        )

    conn.close()
    return grants


def revoke_grant(grant_id: str):
    """Revoke a grant"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE grants SET revoked = 1 WHERE id = ?", (grant_id,))

    cursor.execute(
        """
        INSERT INTO audit_log (id, grant_id, action, details)
        VALUES (?, ?, ?, ?)
    """,
        (secrets.token_urlsafe(8), grant_id, "revoked", "Manually revoked"),
    )

    conn.commit()
    conn.close()


def download_context(grant_id: str) -> str:
    """Download temporary kubeconfig context"""
    grant = get_grant(grant_id)

    if not grant:
        raise ValueError(f"Grant not found: {grant_id}")

    if grant["revoked"]:
        raise ValueError(f"Grant has been revoked: {grant_id}")

    if datetime.now(timezone.utc) > datetime.fromisoformat(
        grant["expires_at"].replace("Z", "+00:00")
    ):
        raise ValueError(f"Grant has expired: {grant_id}")

    encrypted_kc = grant.get("encrypted_kubeconfig")
    if not encrypted_kc:
        # Determine why: check if metadata still exists (legacy path or migration skipped)
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(grants)")
        columns = {col[1]: idx for idx, col in enumerate(cursor.fetchall())}
        if "metadata" in columns:
            cursor.execute("SELECT metadata FROM grants WHERE id = ?", (grant_id,))
            row = cursor.fetchone()
            conn.close()
            if row and row[0]:
                raise ValueError(
                    "Grant has malformed or empty kubeconfig data. Please revoke and re-create this grant."
                )
        else:
            conn.close()
        raise ValueError("Grant has no kubeconfig data — it may need to be re-created.")
    return decrypt_data(encrypted_kc)


def main():
    parser = argparse.ArgumentParser(description="KubeContext Manager")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Create command
    create_parser = subparsers.add_parser("create", help="Create a new grant")
    create_parser.add_argument("--cluster", "-c", required=True, help="Cluster name")
    create_parser.add_argument("--namespace", "-n", help="Namespace (optional)")
    create_parser.add_argument(
        "--role", "-r", default="view", help="Role (view/edit/admin)"
    )
    create_parser.add_argument(
        "--expiry", "-e", type=int, default=4, help="Expiry in hours"
    )

    # List command
    subparsers.add_parser("list", help="List active grants")

    # Revoke command
    revoke_parser = subparsers.add_parser("revoke", help="Revoke a grant")
    revoke_parser.add_argument("grant_id", help="Grant ID")

    # Download command
    download_parser = subparsers.add_parser(
        "download",
        help="Download temporary kubeconfig to a secure file (not stdout)",
    )
    download_parser.add_argument("grant_id", help="Grant ID")
    download_parser.add_argument(
        "--output", "-o", default=None, help="Output file path (default: temp file)"
    )

    # Sync command — push local grants to the API so CLI and API share state
    sync_parser = subparsers.add_parser(
        "sync", help="Push local grants to the KubeTix API"
    )
    sync_parser.add_argument(
        "--api-url",
        default=os.environ.get("KUBETIX_API_URL", "http://localhost:8000"),
        help="KubeTix API base URL (default: $KUBETIX_API_URL or http://localhost:8000)",
    )
    sync_parser.add_argument(
        "--token",
        default=os.environ.get("KUBETIX_API_TOKEN"),
        help="Bearer token for the API (default: $KUBETIX_API_TOKEN)",
    )

    args = parser.parse_args()

    if args.command == "sync":
        sync_to_api(api_url=args.api_url, token=args.token)
        return

    if args.command == "create":
        grant_id = create_grant(args.cluster, args.namespace, args.role, args.expiry)
        print("✅ Grant created!")
        print(f"   ID: {grant_id}")
        print(f"   Cluster: {args.cluster}")
        print(f"   Role: {args.role}")
        print(
            f"   Expires: {datetime.now(timezone.utc) + timedelta(hours=args.expiry)}"
        )
        print(
            f"\nShare this ID with your team or use 'kc-share download {grant_id}' to get the context"
        )

    elif args.command == "list":
        grants = list_grants()
        if not grants:
            print("No active grants")
            return

        print(f"{'ID':<32} {'Cluster':<20} {'Role':<10} {'Expires':<25}")
        print("-" * 87)
        for grant in grants:
            print(
                f"{grant['id']:<32} {grant['cluster_name']:<20} {grant['role']:<10} {grant['expires_at']:<25}"
            )

    elif args.command == "revoke":
        revoke_grant(args.grant_id)
        print(f"✅ Grant {args.grant_id} revoked")

    elif args.command == "download":
        context = download_context(args.grant_id)

        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(context)
        else:
            # Write to a secure temp file with restricted permissions
            import tempfile

            fd, tmp_path = tempfile.mkstemp(suffix="-kubeconfig", prefix=".kc-share-")
            os.close(fd)
            output_path = Path(tmp_path)
            output_path.write_text(context)
            output_path.chmod(0o600)

        print(f"✅ Kubeconfig written securely to: {output_path}")
        print(f"   Use: KUBECONFIG={output_path} kubectl get nodes")

    else:
        parser.print_help()


def sync_to_api(api_url: str, token: Optional[str]) -> None:
    """Push locally stored grants to the KubeTix API.

    The CLI and API historically maintained independent databases and
    independent encryption keys, which meant a grant created by the CLI
    was invisible to the API and vice versa (issue #162). This function
    bridges the silo by POSTing every active, non-revoked grant to the
    API's /grants endpoint, reusing the CLI's existing Fernet encryption
    so the API can decrypt the kubeconfig with the shared key.
    """
    try:
        import urllib.request
        import urllib.error
    except ImportError:  # pragma: no cover - stdlib always present
        raise

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, cluster_name, namespace, role, created_at, expires_at, "
        "revoked, metadata, encrypted_kubeconfig FROM grants WHERE revoked = 0"
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("No grants to sync")
        return

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    synced = 0
    failed = 0
    for row in rows:
        (grant_id, cluster_name, namespace, role, created_at,
         expires_at, revoked, metadata, encrypted_kubeconfig) = row
        payload = {
            "id": grant_id,
            "cluster_name": cluster_name,
            "namespace": namespace,
            "role": role,
            "created_at": created_at,
            "expires_at": expires_at,
            "revoked": bool(revoked),
            "metadata": metadata,
            "encrypted_kubeconfig": encrypted_kubeconfig,
        }
        url = api_url.rstrip("/") + f"/grants/{grant_id}"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="PUT",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if 200 <= resp.status < 300:
                    synced += 1
                else:
                    failed += 1
        except (urllib.error.URLError, urllib.error.HTTPError):
            failed += 1

    print(f"✅ Synced {synced} grant(s) to {api_url} ({failed} failed)")


if __name__ == "__main__":
    main()
