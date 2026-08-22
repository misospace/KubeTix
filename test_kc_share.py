"""
Test suite for KubeContext Manager CLI
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Import directly from file
spec = __import__("importlib.util").util.spec_from_file_location(
    "kc_share", Path(__file__).parent / "kc-share.py"
)
kc_share = __import__("importlib.util").util.module_from_spec(spec)
spec.loader.exec_module(kc_share)

# Import all functions directly
init_db = kc_share.init_db
get_connection = kc_share.get_connection
get_encryption_key = kc_share.get_encryption_key
encrypt_data = kc_share.encrypt_data
decrypt_data = kc_share.decrypt_data
create_grant = kc_share.create_grant
get_grant = kc_share.get_grant
list_grants = kc_share.list_grants
revoke_grant = kc_share.revoke_grant
download_context = kc_share.download_context
DB_PATH = kc_share.DB_PATH
CONFIG_PATH = kc_share.CONFIG_PATH


class TestEncryption(unittest.TestCase):
    """Test encryption/decryption functions"""

    def test_encrypt_decrypt_roundtrip(self):
        """Test that data can be encrypted and decrypted correctly"""
        original = "test-kubeconfig-data"
        encrypted = encrypt_data(original)
        decrypted = decrypt_data(encrypted)
        self.assertEqual(original, decrypted)

    def test_different_keys_produce_different_encryption(self):
        """Test that different keys produce different encrypted output"""
        data = "same-data"
        encrypted1 = encrypt_data(data)
        encrypted2 = encrypt_data(data)
        self.assertNotEqual(encrypted1, encrypted2)


class TestDatabase(unittest.TestCase):
    """Test database operations"""

    def setUp(self):
        """Set up test database"""
        self.test_dir = tempfile.mkdtemp()
        self.test_db = Path(self.test_dir) / "test.sqlite"
        self.test_config = Path(self.test_dir) / "config.json"

        # Patch paths
        kc_share.DB_PATH = self.test_db
        kc_share.CONFIG_PATH = self.test_config

        init_db()

    def tearDown(self):
        """Clean up test database"""
        shutil.rmtree(self.test_dir)

    def test_init_db_creates_tables(self):
        """Test that init_db creates the required tables"""
        conn = get_connection()
        cursor = conn.cursor()

        # Check grants table exists
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='grants'"
        )
        self.assertIsNotNone(cursor.fetchone())

        # Check audit_log table exists
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
        )
        self.assertIsNotNone(cursor.fetchone())

        conn.close()

    def test_grant_persistence(self):
        """Test that grants are persisted to database"""
        test_kubeconfig = Path(self.test_dir) / "config"
        test_kubeconfig.write_text(
            "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []"
        )
        os.environ["KUBECONFIG"] = str(test_kubeconfig)

        grant_id = create_grant("test-cluster", "default", "view", 1)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM grants WHERE id = ?", (grant_id,))
        row = cursor.fetchone()

        self.assertIsNotNone(row)
        self.assertEqual(row[1], "test-cluster")
        self.assertEqual(row[2], "default")
        self.assertEqual(row[3], "view")

        conn.close()


class TestGrantLifecycle(unittest.TestCase):
    """Test complete grant lifecycle"""

    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_db = Path(self.test_dir) / "test.sqlite"
        self.test_config = Path(self.test_dir) / "config.json"
        self.test_kubeconfig = Path(self.test_dir) / "config"

        # Patch paths
        kc_share.DB_PATH = self.test_db
        kc_share.CONFIG_PATH = self.test_config

        # Create test kubeconfig
        self.test_kubeconfig.write_text(
            "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []"
        )
        os.environ["KUBECONFIG"] = str(self.test_kubeconfig)

        # Clean any existing database
        if self.test_db.exists():
            self.test_db.unlink()

        init_db()

    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
        if "KUBECONFIG" in os.environ:
            del os.environ["KUBECONFIG"]

    def test_create_grant(self):
        """Test creating a new grant"""
        grant_id = create_grant("prod-cluster", "production", "edit", 2)

        self.assertIsNotNone(grant_id)
        self.assertIsInstance(grant_id, str)
        self.assertGreater(len(grant_id), 0)

    def test_get_grant(self):
        """Test retrieving a grant"""
        grant_id = create_grant("test-cluster", "default", "view", 1)
        grant = get_grant(grant_id)

        self.assertIsNotNone(grant)
        self.assertEqual(grant["cluster_name"], "test-cluster")
        self.assertEqual(grant["namespace"], "default")
        self.assertEqual(grant["role"], "view")
        self.assertFalse(grant["revoked"])

    def test_get_nonexistent_grant(self):
        """Test retrieving a grant that doesn't exist"""
        grant = get_grant("nonexistent-id")
        self.assertIsNone(grant)

    def test_list_grants(self):
        """Test listing all active grants"""
        create_grant("cluster1", "ns1", "view", 1)
        create_grant("cluster2", "ns2", "edit", 2)

        grants = list_grants()
        self.assertEqual(len(grants), 2)

    def test_revoke_grant(self):
        """Test revoking a grant"""
        grant_id = create_grant("test-cluster", "default", "view", 1)

        revoke_grant(grant_id)

        grant = get_grant(grant_id)
        self.assertIsNotNone(grant)
        self.assertTrue(grant["revoked"])

    def test_download_context(self):
        """Test downloading temporary context"""
        grant_id = create_grant("test-cluster", "default", "view", 1)

        context = download_context(grant_id)

        self.assertIn("apiVersion", context)
        self.assertIn("kind: Config", context)

    def test_download_revoked_grant_fails(self):
        """Test that downloading a revoked grant fails"""
        grant_id = create_grant("test-cluster", "default", "view", 1)
        revoke_grant(grant_id)

        with self.assertRaises(ValueError):
            download_context(grant_id)

    def test_download_expired_grant_fails(self):
        """Test that downloading an expired grant fails"""
        # Create grant with 0 expiry (already expired)
        grant_id = create_grant("test-cluster", "default", "view", 0)

        with self.assertRaises(ValueError):
            download_context(grant_id)

    def test_audit_log_created(self):
        """Test that audit log entries are created"""
        grant_id = create_grant("test-cluster", "default", "view", 1)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_log WHERE grant_id = ?", (grant_id,))
        entries = cursor.fetchall()

        self.assertGreater(len(entries), 0)

        # Check that a "created" entry exists
        actions = [e[2] for e in entries]
        self.assertIn("created", actions)

        conn.close()


class TestExpiry(unittest.TestCase):
    """Test grant expiry logic"""

    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_db = Path(self.test_dir) / "test.sqlite"
        self.test_config = Path(self.test_dir) / "config.json"
        self.test_kubeconfig = Path(self.test_dir) / "config"

        # Reset global paths - this is critical to isolate tests
        kc_share.DB_PATH = self.test_db
        kc_share.CONFIG_PATH = self.test_config

        self.test_kubeconfig.write_text(
            "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []"
        )
        os.environ["KUBECONFIG"] = str(self.test_kubeconfig)

        # Clean any existing database
        if self.test_db.exists():
            self.test_db.unlink()

        # Reinitialize database with new paths
        kc_share.init_db()

    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
        if "KUBECONFIG" in os.environ:
            del os.environ["KUBECONFIG"]

    def test_expired_grant_not_in_list(self):
        """Test that expired grants don't appear in list"""
        # Create grant with 0 expiry (already expired)
        create_grant("test-cluster", "default", "view", 0)

        grants = list_grants()
        self.assertEqual(len(grants), 0)


class TestMissingCryptography(unittest.TestCase):
    """Test that a missing cryptography dependency fails loudly without pip install"""

    def test_missing_cryptography_fails_loudly(self):
        """kc-share.py must exit 1 with install instructions, never shell out to pip"""
        # Shadow the real cryptography package with one that raises ImportError
        shadow_dir = Path(tempfile.mkdtemp())
        try:
            (shadow_dir / "cryptography").mkdir()
            (shadow_dir / "cryptography" / "__init__.py").write_text(
                'raise ImportError("blocked for test")\n'
            )
            env = dict(os.environ)
            env["PYTHONPATH"] = str(shadow_dir) + os.pathsep + env.get("PYTHONPATH", "")
            result = subprocess.run(
                [sys.executable, str(Path(__file__).parent / "kc-share.py"), "--help"],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("pip install -r requirements-cli.txt", result.stderr)
            self.assertNotIn("Installing cryptography", result.stderr)
        finally:
            shutil.rmtree(shadow_dir)


if __name__ == "__main__":
    unittest.main(verbosity=2)
