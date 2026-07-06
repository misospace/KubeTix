"""
Regression tests for kc-share schema migration (issue #67).

Tests that the init_db() migration properly converts legacy grants
stored with encrypted kubeconfig in a JSON metadata field into the
new dedicated encrypted_kubeconfig column, and handles edge cases.
"""

import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

# Import directly from file — kc-share.py is at repo root (2 levels up)
spec = __import__("importlib.util").util.spec_from_file_location(
    "kc_share",
    Path(__file__).parent.parent.parent / "kc-share.py",
)
kc_share = __import__("importlib.util").util.module_from_spec(spec)
spec.loader.exec_module(kc_share)

init_db = kc_share.init_db
get_connection = kc_share.get_connection
encrypt_data = kc_share.encrypt_data
decrypt_data = kc_share.decrypt_data
download_context = kc_share.download_context


class TestMigrationLegacyMetadata(unittest.TestCase):
    """Test migration of legacy metadata-stored grants to new schema."""

    def setUp(self):
        """Set up isolated test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_db = Path(self.test_dir) / "test.sqlite"
        self.test_config = Path(self.test_dir) / "config.json"

        # Patch paths before any db operations
        kc_share.DB_PATH = self.test_db
        kc_share.CONFIG_PATH = self.test_config

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
        if "KUBECONFIG" in os.environ:
            del os.environ["KUBECONFIG"]

    def _create_legacy_db(self):
        """Create a database with the old v1 schema (metadata-based storage)."""
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()

        # Create grants table WITHOUT encrypted_kubeconfig column (v1 schema)
        cursor.execute("""
            CREATE TABLE grants (
                id TEXT PRIMARY KEY,
                cluster_name TEXT NOT NULL,
                namespace TEXT,
                role TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                revoked BOOLEAN DEFAULT 0,
                metadata TEXT
            )
        """)

        # Create audit_log with old 'timestamp' column name
        cursor.execute("""
            CREATE TABLE audit_log (
                id TEXT PRIMARY KEY,
                grant_id TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        """)

        # Create schema_version at v1
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)"
        )
        cursor.execute("INSERT INTO schema_version VALUES (1)")

        conn.commit()
        return conn

    def _insert_legacy_grant(
        self, conn, grant_id, cluster_name, encrypted_kc_in_metadata
    ):
        """Insert a legacy-format grant with kubeconfig in metadata."""
        metadata = {"kubeconfig_encrypted": encrypted_kc_in_metadata}
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO grants (id, cluster_name, namespace, role, expires_at, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                grant_id,
                cluster_name,
                "default",
                "view",
                (
                    datetime.now(timezone.utc).replace(microsecond=0)
                    + __import__("datetime").timedelta(hours=1)
                ).isoformat(),
                json.dumps(metadata),
            ),
        )
        conn.commit()

    def test_migration_adds_encrypted_kubeconfig_column(self):
        """Verify that migration adds the encrypted_kubeconfig column to existing grants table."""
        conn = self._create_legacy_db()
        conn.close()

        # Run init_db which should trigger migration
        init_db()

        # Check that encrypted_kubeconfig column now exists
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(grants)")
        columns = [col[1] for col in cursor.fetchall()]
        conn.close()

        self.assertIn("encrypted_kubeconfig", columns)

    def test_migration_adds_schema_version_table(self):
        """Verify that migration creates the schema_version table."""
        conn = self._create_legacy_db()
        conn.close()

        init_db()

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
        )
        result = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(result)

    def test_migration_migrates_metadata_to_encrypted_kubeconfig(self):
        """Verify that legacy grants with metadata are migrated to encrypted_kubeconfig column."""
        # Create legacy DB
        conn = self._create_legacy_db()

        # Generate an encryption key and encrypt a kubeconfig
        kc = "apiVersion: v1\nkind: Config\ntest-data"
        encrypted_kc = encrypt_data(kc)

        # Insert legacy grant
        grant_id = "test-legacy-grant-id"
        self._insert_legacy_grant(conn, grant_id, "test-cluster", encrypted_kc)
        conn.close()

        # Run migration
        init_db()

        # Verify the grant was migrated
        grant = kc_share.get_grant(grant_id)
        self.assertIsNotNone(grant)
        self.assertIsNotNone(grant["encrypted_kubeconfig"])
        self.assertNotEqual(
            grant["encrypted_kubeconfig"], encrypted_kc
        )  # Re-encrypted with new key

        # Verify we can decrypt the migrated kubeconfig
        decrypted = decrypt_data(grant["encrypted_kubeconfig"])
        self.assertEqual(decrypted, kc)

    def test_migration_reencrypts_with_current_key(self):
        """Verify that migration re-encrypts data with the current encryption key."""
        conn = self._create_legacy_db()

        # Generate a specific key and encrypt
        kc = "apiVersion: v1\nkind: Config\ntest-data"
        old_key = kc_share.get_encryption_key()  # Get the current key first
        fernet_old = __import__("cryptography.fernet").fernet.Fernet(old_key.encode())
        old_encrypted = fernet_old.encrypt(kc.encode()).decode()

        self._insert_legacy_grant(
            conn, "test-key-rotation", "test-cluster", old_encrypted
        )
        conn.close()

        # Generate a NEW key (simulate key rotation)
        new_key = kc_share.Fernet.generate_key().decode()
        kc_share.CONFIG_PATH.write_text(json.dumps({"encryption_key": new_key}))

        # Run migration — should re-encrypt with the new key
        init_db()

        # Verify we can still decrypt with the new key
        grant = kc_share.get_grant("test-key-rotation")
        self.assertIsNotNone(grant)
        decrypted = decrypt_data(grant["encrypted_kubeconfig"])
        self.assertEqual(decrypted, kc)

    def test_migration_skips_malformed_metadata(self):
        """Verify that malformed metadata is skipped gracefully during migration."""
        conn = self._create_legacy_db()
        cursor = conn.cursor()

        # Insert a grant with invalid JSON in metadata
        cursor.execute(
            "INSERT INTO grants (id, cluster_name, namespace, role, expires_at, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "test-bad-metadata",
                "bad-cluster",
                "default",
                "view",
                datetime.now(timezone.utc).isoformat(),
                "NOT VALID JSON{{}",
            ),
        )

        # Insert a valid grant alongside
        kc = "apiVersion: v1\nkind: Config\ntest-data"
        encrypted_kc = encrypt_data(kc)
        self._insert_legacy_grant(conn, "test-good-grant", "good-cluster", encrypted_kc)
        conn.close()

        # Migration should not crash
        init_db()

        # Good grant should be migrated
        good_grant = kc_share.get_grant("test-good-grant")
        self.assertIsNotNone(good_grant)
        self.assertIsNotNone(good_grant["encrypted_kubeconfig"])

        # Bad grant should still exist but without encrypted_kubeconfig
        bad_grant = kc_share.get_grant("test-bad-metadata")
        self.assertIsNotNone(bad_grant)
        self.assertIsNone(bad_grant["encrypted_kubeconfig"])

    def test_migration_renames_audit_log_timestamp_to_created_at(self):
        """Verify that audit_log.timestamp is renamed to created_at during migration."""
        conn = self._create_legacy_db()
        conn.close()

        init_db()

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(audit_log)")
        columns = [col[1] for col in cursor.fetchall()]
        conn.close()

        self.assertIn("created_at", columns)
        self.assertNotIn("timestamp", columns)

    def test_migration_preserves_existing_grants(self):
        """Verify that all existing grants are preserved after migration."""
        conn = self._create_legacy_db()

        # Insert multiple legacy grants
        for i in range(3):
            kc = f"apiVersion: v1\nkind: Config\ncluster-{i}"
            encrypted_kc = encrypt_data(kc)
            self._insert_legacy_grant(conn, f"grant-{i}", f"cluster-{i}", encrypted_kc)
        conn.close()

        init_db()

        # All grants should still be accessible
        for i in range(3):
            grant = kc_share.get_grant(f"grant-{i}")
            self.assertIsNotNone(grant)
            self.assertEqual(grant["cluster_name"], f"cluster-{i}")
            self.assertIsNotNone(grant["encrypted_kubeconfig"])

    def test_migration_downloads_after_migration(self):
        """End-to-end: create legacy grant, migrate, then download context."""
        conn = self._create_legacy_db()

        kc = "apiVersion: v1\nkind: Config\nclusters:\n- name: test\ncontexts: []\nusers: []"
        encrypted_kc = encrypt_data(kc)
        self._insert_legacy_grant(conn, "test-download", "test-cluster", encrypted_kc)
        conn.close()

        init_db()

        # Should be able to download the migrated kubeconfig
        context = download_context("test-download")
        self.assertIn("apiVersion", context)
        self.assertIn("kind: Config", context)


class TestFreshInstall(unittest.TestCase):
    """Test that fresh installs work correctly with new schema."""

    def setUp(self):
        """Set up isolated test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_db = Path(self.test_dir) / "test.sqlite"
        self.test_config = Path(self.test_dir) / "config.json"

        kc_share.DB_PATH = self.test_db
        kc_share.CONFIG_PATH = self.test_config

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
        if "KUBECONFIG" in os.environ:
            del os.environ["KUBECONFIG"]

    def test_fresh_install_has_new_schema(self):
        """Verify that a fresh install creates the new schema directly."""
        init_db()

        conn = get_connection()
        cursor = conn.cursor()

        # Check grants table has encrypted_kubeconfig column
        cursor.execute("PRAGMA table_info(grants)")
        columns = [col[1] for col in cursor.fetchall()]
        self.assertIn("encrypted_kubeconfig", columns)

        # Check audit_log has created_at
        cursor.execute("PRAGMA table_info(audit_log)")
        columns = [col[1] for col in cursor.fetchall()]
        self.assertIn("created_at", columns)

        # Check schema_version is at v2
        cursor.execute("SELECT version FROM schema_version LIMIT 1")
        row = cursor.fetchone()
        self.assertEqual(row[0], 2)

        conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
