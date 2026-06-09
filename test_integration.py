"""
Integration tests for KubeContext Manager CLI
Tests the full CLI workflow and edge cases
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Import directly from file
spec = __import__("importlib.util").util.spec_from_file_location(
    "kc_share", Path(__file__).parent / "kc-share.py"
)
kc_share = __import__("importlib.util").util.module_from_spec(spec)
spec.loader.exec_module(kc_share)


class TestCLIIntegration(unittest.TestCase):
    """Integration tests for CLI commands"""

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
        self.test_kubeconfig.write_text("""
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://test-cluster.example.com:6443
    insecure-skip-tls-verify: true
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token-12345
""")
        os.environ["KUBECONFIG"] = str(self.test_kubeconfig)

        # Clean any existing database
        if self.test_db.exists():
            self.test_db.unlink()

        kc_share.init_db()

    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
        if "KUBECONFIG" in os.environ:
            del os.environ["KUBECONFIG"]

    def test_cli_create_command(self):
        """Test CLI create command"""
        result = subprocess.run(
            [
                sys.executable,
                "kc-share.py",
                "create",
                "--cluster",
                "prod",
                "--role",
                "edit",
                "--expiry",
                "4",
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
        )

        self.assertEqual(
            result.returncode,
            0,
            f"create failed: stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        self.assertIn("Grant created!", result.stdout)
        self.assertIn("prod", result.stdout)
        self.assertIn("edit", result.stdout)

    def test_cli_list_command(self):
        """Test CLI list command"""
        # First create a grant
        subprocess.run(
            [
                sys.executable,
                "kc-share.py",
                "create",
                "--cluster",
                "test",
                "--role",
                "view",
                "--expiry",
                "1",
            ],
            capture_output=True,
            cwd=Path(__file__).parent,
        )

        # Then list it
        result = subprocess.run(
            [sys.executable, "kc-share.py", "list"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("test", result.stdout)
        self.assertIn("view", result.stdout)

    def test_cli_revoke_command(self):
        """Test CLI revoke command"""
        # Create a grant first
        create_result = subprocess.run(
            [
                sys.executable,
                "kc-share.py",
                "create",
                "--cluster",
                "test",
                "--role",
                "view",
                "--expiry",
                "1",
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
        )

        # Extract grant ID from output
        grant_id = create_result.stdout.split("ID: ")[1].strip().split("\n")[0]

        # Revoke it
        result = subprocess.run(
            [sys.executable, "kc-share.py", "revoke", grant_id],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
        )

        self.assertEqual(
            result.returncode,
            0,
            f"revoke failed: stdout={result.stdout!r} stderr={result.stderr!r} grant_id={grant_id!r}",
        )
        self.assertIn("revoked", result.stdout)

    def test_cli_download_command(self):
        """Test CLI download writes kubeconfig to secure file, not stdout"""
        # Create a grant first
        create_result = subprocess.run(
            [
                sys.executable,
                "kc-share.py",
                "create",
                "--cluster",
                "test",
                "--role",
                "view",
                "--expiry",
                "1",
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
        )

        # Extract grant ID from output
        grant_id = create_result.stdout.split("ID: ")[1].strip().split("\n")[0]

        # Download it
        result = subprocess.run(
            [sys.executable, "kc-share.py", "download", grant_id],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
        )

        self.assertEqual(result.returncode, 0)
        self.assertNotIn("apiVersion", result.stdout)
        self.assertNotIn("kind: Config", result.stdout)
        self.assertIn("written securely to", result.stdout)
        self.assertIn("KUBECONFIG=", result.stdout)
        output_path = result.stdout.split("to: ")[1].strip().split("\n")[0]
        self.assertTrue(Path(output_path).exists())
        self.assertEqual(Path(output_path).stat().st_mode & 0o777, 0o600)
        file_content = Path(output_path).read_text()
        self.assertIn("apiVersion", file_content)
        self.assertIn("kind: Config", file_content)
        self.assertNotIn("apiVersion", result.stdout)
        self.assertNotIn("kind: Config", result.stdout)
        self.assertIn("written securely to", result.stdout)
        self.assertIn("KUBECONFIG=", result.stdout)
        output_path = result.stdout.split("to: ")[1].strip().split("\n")[0]
        self.assertTrue(Path(output_path).exists())
        self.assertEqual(Path(output_path).stat().st_mode & 0o777, 0o600)
        file_content = Path(output_path).read_text()
        self.assertIn("apiVersion", file_content)
        self.assertIn("kind: Config", file_content)

    def test_cli_download_with_output_flag(self):
        """Test CLI download command with custom --output path"""
        import tempfile

        # Create a grant first
        create_result = subprocess.run(
            [
                sys.executable,
                "kc-share.py",
                "create",
                "--cluster",
                "test",
                "--role",
                "view",
                "--expiry",
                "1",
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
        )

        grant_id = create_result.stdout.split("ID: ")[1].strip().split("\n")[0]

        # Download to a custom output path
        with tempfile.NamedTemporaryFile(suffix="-kubeconfig", delete=False) as tf:
            output_path = tf.name

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "kc-share.py",
                    "download",
                    grant_id,
                    "--output",
                    output_path,
                ],
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent,
            )

            self.assertEqual(result.returncode, 0)
            self.assertIn(output_path, result.stdout)
            self.assertTrue(Path(output_path).exists())
            file_content = Path(output_path).read_text()
            self.assertIn("apiVersion", file_content)
            self.assertIn("kind: Config", file_content)
        finally:
            Path(output_path).unlink(missing_ok=True)

    def test_cli_help_command(self):
        """Test CLI help command"""
        result = subprocess.run(
            [sys.executable, "kc-share.py", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("KubeContext Manager", result.stdout)
        self.assertIn("create", result.stdout)
        self.assertIn("list", result.stdout)
        self.assertIn("revoke", result.stdout)
        self.assertIn("download", result.stdout)

    def test_cli_subcommand_help(self):
        """Test CLI subcommand help"""
        result = subprocess.run(
            [sys.executable, "kc-share.py", "create", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("--cluster", result.stdout)
        self.assertIn("--namespace", result.stdout)
        self.assertIn("--role", result.stdout)
        self.assertIn("--expiry", result.stdout)


class TestEdgeCases(unittest.TestCase):
    """Edge case and error handling tests"""

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

        kc_share.init_db()

    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
        if "KUBECONFIG" in os.environ:
            del os.environ["KUBECONFIG"]

    def test_grant_with_special_characters(self):
        """Test grant with special characters in cluster name"""
        grant_id = kc_share.create_grant("prod-cluster-123!@#", "default", "view", 1)

        self.assertIsNotNone(grant_id)
        grant = kc_share.get_grant(grant_id)
        self.assertEqual(grant["cluster_name"], "prod-cluster-123!@#")

    def test_grant_with_long_namespace(self):
        """Test grant with very long namespace"""
        long_ns = "a" * 200
        grant_id = kc_share.create_grant("test-cluster", long_ns, "view", 1)

        self.assertIsNotNone(grant_id)
        grant = kc_share.get_grant(grant_id)
        self.assertEqual(grant["namespace"], long_ns)

    def test_multiple_concurrent_grants(self):
        """Test creating multiple grants concurrently"""
        grant_ids = []
        for i in range(10):
            grant_id = kc_share.create_grant(f"cluster-{i}", f"ns-{i}", "view", 1)
            grant_ids.append(grant_id)

        grants = kc_share.list_grants()
        self.assertEqual(len(grants), 10)

        # Verify all grants are retrievable
        for grant_id in grant_ids:
            grant = kc_share.get_grant(grant_id)
            self.assertIsNotNone(grant)

    def test_grant_expiry_boundary(self):
        """Test grant expiry at boundary"""
        # Create grant with 1 second expiry
        grant_id = kc_share.create_grant("test-cluster", "default", "view", 0)

        # Should not appear in list (already expired)
        grants = kc_share.list_grants()
        self.assertEqual(len(grants), 0)

    def test_audit_log_completeness(self):
        """Test that audit log captures all actions"""
        grant_id = kc_share.create_grant("test-cluster", "default", "view", 1)

        # Create audit entries for create, revoke
        kc_share.revoke_grant(grant_id)

        conn = kc_share.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT action FROM audit_log WHERE grant_id = ?", (grant_id,))
        actions = [row[0] for row in cursor.fetchall()]

        self.assertIn("created", actions)
        self.assertIn("revoked", actions)

        conn.close()

    def test_grant_metadata_integrity(self):
        """Test that grant metadata is preserved correctly"""
        grant_id = kc_share.create_grant("prod-cluster", "production", "admin", 24)

        grant = kc_share.get_grant(grant_id)

        self.assertEqual(grant["cluster_name"], "prod-cluster")
        self.assertEqual(grant["namespace"], "production")
        self.assertEqual(grant["role"], "admin")
        self.assertIsNotNone(grant.get("encrypted_kubeconfig"))


class TestSecurity(unittest.TestCase):
    """Security-focused integration tests"""

    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_db = Path(self.test_dir) / "test.sqlite"
        self.test_config = Path(self.test_dir) / "config.json"
        self.test_kubeconfig = Path(self.test_dir) / "config"

        # Patch paths
        kc_share.DB_PATH = self.test_db
        kc_share.CONFIG_PATH = self.test_config

        # Create test kubeconfig with sensitive data
        self.test_kubeconfig.write_text("""
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://prod.example.com:6443
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t
  name: prod-cluster
contexts:
- context:
    cluster: prod-cluster
    user: admin-user
  name: prod-context
current-context: prod-context
users:
- name: admin-user
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t
    client-key-data: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t
""")
        os.environ["KUBECONFIG"] = str(self.test_kubeconfig)

        # Clean any existing database
        if self.test_db.exists():
            self.test_db.unlink()

        kc_share.init_db()

    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
        if "KUBECONFIG" in os.environ:
            del os.environ["KUBECONFIG"]

    def test_kubeconfig_encrypted_in_db(self):
        """Test that kubeconfig is encrypted in database"""
        grant_id = kc_share.create_grant("prod-cluster", "default", "admin", 1)

        conn = kc_share.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT encrypted_kubeconfig FROM grants WHERE id = ?", (grant_id,)
        )
        row = cursor.fetchone()

        encrypted = row[0]
        self.assertIsNotNone(encrypted)

        # Should be encrypted (not plain text)
        self.assertNotIn("client-key-data", encrypted)
        self.assertNotIn("certificate-authority-data", encrypted)

        conn.close()

    def test_decrypted_kubeconfig_integrity(self):
        """Test that decrypted kubeconfig matches original"""
        original_kubeconfig = self.test_kubeconfig.read_text()

        grant_id = kc_share.create_grant("prod-cluster", "default", "admin", 1)
        decrypted = kc_share.download_context(grant_id)

        self.assertEqual(original_kubeconfig.strip(), decrypted.strip())

    def test_encryption_key_isolated(self):
        """Test that encryption key is isolated per test"""
        # Create grant in this test
        grant_id = kc_share.create_grant("test-cluster", "default", "view", 1)

        # Get encrypted data
        conn = kc_share.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT encrypted_kubeconfig FROM grants WHERE id = ?", (grant_id,)
        )
        row = cursor.fetchone()
        encrypted = row[0]
        self.assertIsNotNone(encrypted)
        conn.close()

        # Create new test environment (new key)
        new_test_dir = tempfile.mkdtemp()
        new_db = Path(new_test_dir) / "test.sqlite"
        new_config = Path(new_test_dir) / "config.json"
        new_kubeconfig = Path(new_test_dir) / "config"

        kc_share.DB_PATH = new_db
        kc_share.CONFIG_PATH = new_config

        new_kubeconfig.write_text(
            "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []"
        )
        os.environ["KUBECONFIG"] = str(new_kubeconfig)

        if new_db.exists():
            new_db.unlink()

        kc_share.init_db()

        # Create another grant
        new_grant_id = kc_share.create_grant("test-cluster", "default", "view", 1)

        conn = kc_share.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT encrypted_kubeconfig FROM grants WHERE id = ?", (new_grant_id,)
        )
        row = cursor.fetchone()
        new_encrypted = row[0]
        self.assertIsNotNone(new_encrypted)
        conn.close()

        # Should be different encryption
        self.assertNotEqual(encrypted, new_encrypted)

        shutil.rmtree(new_test_dir)


if __name__ == "__main__":
    unittest.main(verbosity=2)
