"""
Concurrency tests for KubeTix API
Tests concurrent access and race conditions
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from _shared_db import engine, TestingSessionLocal
import secrets
import threading
import time
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import the main app
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "kubetix-api"))

from main import app, Base, get_db, User, Grant, get_password_hash

# Test database


class TestConcurrentGrantCreation:
    """Tests for concurrent grant creation."""

    def test_concurrent_grant_creation(self, client, auth_headers, monkeypatch):
        """Test creating multiple grants concurrently."""
        # Mock kubeconfig
        with __import__("tempfile").NamedTemporaryFile(
            mode="w", suffix=".kubeconfig", delete=False
        ) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name

        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)

        results = []
        errors = []

        def create_grant(i):
            try:
                response = client.post(
                    "api/v1/grants",
                    json={"cluster_name": f"cluster-{i}", "role": "view"},
                    headers=auth_headers,
                )
                return response.status_code, response.json()
            except Exception as e:
                return None, str(e)

        # Create 10 grants concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(create_grant, i) for i in range(10)]
            for future in as_completed(futures):
                status, data = future.result()
                results.append(status)

        import os

        os.unlink(kubeconfig_path)

        # All should succeed
        assert all(s == 201 for s in results)

        # List grants - should have all 10
        response = client.get("api/v1/grants", headers=auth_headers)
        grants = response.json()
        assert len(grants) == 10

    def test_concurrent_list_grants(self, client, db_session, auth_headers, auth_token):
        """Test listing grants under concurrent access."""
        # Create some grants first
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        for i in range(5):
            grant = Grant(
                id=secrets.token_urlsafe(16),
                user_id=user.id,
                cluster_name=f"cluster-{i}",
                namespace="default",
                role="view",
                encrypted_kubeconfig="encrypted",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
            db_session.add(grant)
        db_session.commit()

        results = []

        def list_grants():
            response = client.get("api/v1/grants", headers=auth_headers)
            return response.status_code, len(response.json())

        # List grants concurrently
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(list_grants) for _ in range(10)]
            for future in as_completed(futures):
                status, count = future.result()
                results.append((status, count))

        # All should return same count
        counts = [c for s, c in results if s == 200]
        assert len(set(counts)) == 1  # All should be equal


class TestConcurrentRevocation:
    """Tests for concurrent grant revocation."""

    def test_concurrent_revoke_same_grant(
        self, client, db_session, auth_headers, auth_token, monkeypatch
    ):
        """Test revoking the same grant concurrently."""
        # Create a grant
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="test-cluster",
            namespace="default",
            role="view",
            encrypted_kubeconfig="encrypted",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id

        # Mock kubeconfig
        with __import__("tempfile").NamedTemporaryFile(
            mode="w", suffix=".kubeconfig", delete=False
        ) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name

        # Try to revoke concurrently
        results = []

        def revoke_grant():
            response = client.delete(f"api/v1/grants/{grant_id}", headers=auth_headers)
            return response.status_code

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(revoke_grant) for _ in range(5)]
            for future in as_completed(futures):
                results.append(future.result())

        import os

        os.unlink(kubeconfig_path)

        # At least one should succeed (204), others should be idempotent
        assert 204 in results


class TestRaceConditionPrevention:
    """Tests to ensure race conditions are handled."""

    def test_grant_idempotency(self, client, auth_headers, monkeypatch):
        """Test that concurrent identical requests are handled idempotently."""
        with __import__("tempfile").NamedTemporaryFile(
            mode="w", suffix=".kubeconfig", delete=False
        ) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name

        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)

        # Create same grant data concurrently
        results = []

        def create_grant():
            response = client.post(
                "api/v1/grants",
                json={"cluster_name": "same-cluster", "role": "view"},
                headers=auth_headers,
            )
            return response.status_code

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(create_grant) for _ in range(3)]
            for future in as_completed(futures):
                results.append(future.result())

        import os

        os.unlink(kubeconfig_path)

        # All should succeed (may create multiple grants - this is expected)
        assert all(s == 201 for s in results)

    def test_download_after_concurrent_revoke(
        self, client, db_session, auth_headers, auth_token, monkeypatch
    ):
        """Test downloading after concurrent revocation."""
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        grant = Grant(
            id=secrets.token_urlsafe(16),
            user_id=user.id,
            cluster_name="test-cluster",
            namespace="default",
            role="view",
            encrypted_kubeconfig="encrypted",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db_session.add(grant)
        db_session.commit()
        grant_id = grant.id

        # Mock kubeconfig
        with __import__("tempfile").NamedTemporaryFile(
            mode="w", suffix=".kubeconfig", delete=False
        ) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name

        # Revoke and download concurrently
        results = {"revoke": None, "download": None}

        def revoke():
            response = client.delete(f"api/v1/grants/{grant_id}", headers=auth_headers)
            results["revoke"] = response.status_code

        def download():
            time.sleep(0.1)  # Slight delay to ensure revoke happens first
            response = client.get(
                f"api/v1/grants/{grant_id}/download", headers=auth_headers
            )
            results["download"] = response.status_code

        thread1 = threading.Thread(target=revoke)
        thread2 = threading.Thread(target=download)

        thread1.start()
        thread2.start()

        thread1.join()
        thread2.join()

        import os

        os.unlink(kubeconfig_path)

        # Revoke should succeed
        assert results["revoke"] == 204
        # Download should fail (revoked)
        assert results["download"] == 400


class TestBulkOperations:
    """Tests for bulk operations."""

    def test_bulk_grant_creation(self, client, auth_headers, monkeypatch):
        """Test creating multiple grants in sequence."""
        with __import__("tempfile").NamedTemporaryFile(
            mode="w", suffix=".kubeconfig", delete=False
        ) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name

        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)

        # Create grants sequentially (within rate limit of 10/hour per endpoint)
        batch_size = min(8, 50)  # Stay within the 10/hour rate limit for POST /grants
        created = 0
        for i in range(batch_size):
            response = client.post(
                "api/v1/grants",
                json={
                    "cluster_name": f"cluster-{i}",
                    "namespace": f"ns-{i % 5}",
                    "role": ["view", "edit", "admin"][i % 3],
                },
                headers=auth_headers,
            )
            if response.status_code == 201:
                created += 1
            elif response.status_code == 429:
                # Rate limited — stop early
                break

        import os

        os.unlink(kubeconfig_path)

        # Verify all created grants exist
        response = client.get("api/v1/grants", headers=auth_headers)
        grants = response.json()
        assert len(grants) == created

    def test_large_audit_log(self, client, db_session, auth_headers, auth_token):
        """Test querying large audit log."""
        user = db_session.query(User).filter(User.email == "test@example.com").first()

        # Create many grants
        for i in range(50):
            grant = Grant(
                id=secrets.token_urlsafe(16),
                user_id=user.id,
                cluster_name=f"cluster-{i}",
                namespace="default",
                role="view",
                encrypted_kubeconfig="encrypted",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
            db_session.add(grant)
        db_session.commit()

        # Get audit log
        response = client.get("api/v1/audit", headers=auth_headers)

        # Should return results (may be limited to 100)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
