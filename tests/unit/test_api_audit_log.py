"""
Unit tests for KubeTix API - Audit Log endpoint
Tests the /audit endpoint and audit log entries created by grant operations
"""

import pytest
import json
from datetime import datetime, timezone, timedelta
import secrets
import os
import tempfile
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from _shared_db import engine, TestingSessionLocal
from fastapi.testclient import TestClient
from pathlib import Path

# Set encryption key before importing main
os.environ["KUBECONFIG_ENCRYPTION_KEY"] = "NJGBGddzqA6EVxj4Ld4yDGOmBi2srREevbPY7Z7JNso="

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "kubetix-api"))
from main import app, Base, get_db, User, Grant, AuditLog, get_password_hash, create_access_token

# Test database (in-memory SQLite)
_TEST_DB_URL = f"sqlite:///:memory:?dbname=audit_log_{secrets.token_hex(4)}"
_engine = create_engine(_TEST_DB_URL, connect_args={"check_same_thread": False}, poolclass=StaticPool)
_TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)



class TestAuditLogEndpoint:
    """Tests for the /audit log endpoint."""
    
    def test_audit_log_unauthorized(self, client):
        response = client.get("/audit")
        assert response.status_code == 401
    
    def test_audit_log_empty_for_user(self, client, auth_headers):
        response = client.get("/audit", headers=auth_headers)
        assert response.status_code == 200
        assert response.json() == []
    
    def test_audit_log_contains_grant_creation(self, client, db, auth_headers, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        response = client.post("/grants", json={"cluster_name": "audit-test-cluster", "role": "view"}, headers=auth_headers)
        os.unlink(kubeconfig_path)
        assert response.status_code == 201
        audit_response = client.get("/audit", headers=auth_headers)
        assert audit_response.status_code == 200
        logs = audit_response.json()
        assert len(logs) >= 1
        creation_entries = [log for log in logs if log["action"] == "created"]
        assert len(creation_entries) >= 1
        assert "audit-test-cluster" in creation_entries[0]["details"]
    
    def test_audit_log_contains_grant_revocation(self, client, db, auth_headers, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        client.post("/grants", json={"cluster_name": "revoke-test-cluster", "role": "view"}, headers=auth_headers)
        grants_response = client.get("/grants", headers=auth_headers)
        grant_id = grants_response.json()[0]["id"]
        revoke_response = client.delete(f"/grants/{grant_id}", headers=auth_headers)
        assert revoke_response.status_code == 204
        os.unlink(kubeconfig_path)
        audit_response = client.get("/audit", headers=auth_headers)
        logs = audit_response.json()
        revoke_entries = [log for log in logs if log["action"] == "revoked"]
        assert len(revoke_entries) >= 1
    
    def test_audit_log_fields(self, client, db, auth_headers, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        client.post("/grants", json={"cluster_name": "fields-test-cluster", "role": "view"}, headers=auth_headers)
        os.unlink(kubeconfig_path)
        audit_response = client.get("/audit", headers=auth_headers)
        logs = audit_response.json()
        assert len(logs) >= 1
        entry = logs[0]
        for field in {"id", "user_id", "grant_id", "action", "details", "created_at"}:
            assert field in entry, f"Missing field: {field}"
    
    def test_audit_log_ordering_descending(self, client, db, auth_headers, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        for i in range(3):
            client.post("/grants", json={"cluster_name": f"ordering-cluster-{i}", "role": "view"}, headers=auth_headers)
        os.unlink(kubeconfig_path)
        audit_response = client.get("/audit", headers=auth_headers)
        logs = audit_response.json()
        assert len(logs) >= 3
        for i in range(len(logs) - 1):
            assert logs[i]["created_at"] >= logs[i + 1]["created_at"]
    
    def test_audit_log_limit(self, client, db, auth_headers, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        for i in range(150):
            client.post("/grants", json={"cluster_name": f"limit-cluster-{i}", "role": "view"}, headers=auth_headers)
        os.unlink(kubeconfig_path)
        audit_response = client.get("/audit", headers=auth_headers)
        logs = audit_response.json()
        assert len(logs) <= 100
    
    def test_audit_log_user_only_sees_own_entries(self, client, db, other_headers, admin_token, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        admin_response = client.post("/grants", json={"cluster_name": "admin-cluster", "role": "view"}, headers={"Authorization": f"Bearer {admin_token}"})
        assert admin_response.status_code == 201
        user_response = client.post("/grants", json={"cluster_name": "user-cluster", "role": "view"}, headers=other_headers)
        assert user_response.status_code == 201
        os.unlink(kubeconfig_path)
        audit_response = client.get("/audit", headers=other_headers)
        logs = audit_response.json()
        user_entries = [log for log in logs if "user-cluster" in log.get("details", "")]
        admin_entries = [log for log in logs if "admin-cluster" in log.get("details", "")]
        assert len(user_entries) >= 1
        assert len(admin_entries) == 0
    
    def test_audit_log_admin_sees_all_entries(self, client, db, admin_headers, other_token, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        admin_response = client.post("/grants", json={"cluster_name": "admin-audit-cluster", "role": "view"}, headers=admin_headers)
        assert admin_response.status_code == 201
        client.post("/grants", json={"cluster_name": "user-audit-cluster", "role": "view"}, headers={"Authorization": f"Bearer {other_token}"})
        os.unlink(kubeconfig_path)
        audit_response = client.get("/audit", headers=admin_headers)
        logs = audit_response.json()
        admin_entries = [log for log in logs if "admin-audit-cluster" in log.get("details", "")]
        user_entries = [log for log in logs if "user-audit-cluster" in log.get("details", "")]
        assert len(admin_entries) >= 1
        assert len(user_entries) >= 1


class TestAuditLogIntegration:
    """Integration tests for audit log with grant operations."""
    
    def test_full_lifecycle_audit_trail(self, client, db, auth_headers, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        create_response = client.post("/grants", json={"cluster_name": "lifecycle-cluster", "role": "edit"}, headers=auth_headers)
        assert create_response.status_code == 201
        grant_id = create_response.json()["id"]
        os.unlink(kubeconfig_path)
        revoke_response = client.delete(f"/grants/{grant_id}", headers=auth_headers)
        assert revoke_response.status_code == 204
        audit_response = client.get("/audit", headers=auth_headers)
        logs = audit_response.json()
        actions = [log["action"] for log in logs]
        assert "created" in actions
        assert "revoked" in actions
        created_entry = next(log for log in logs if log["action"] == "created")
        revoked_entry = next(log for log in logs if log["action"] == "revoked")
        assert created_entry["grant_id"] == grant_id
        assert revoked_entry["grant_id"] == grant_id
    
    def test_audit_log_grant_id_present(self, client, db, auth_headers, monkeypatch):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.kubeconfig', delete=False) as f:
            f.write("apiVersion: v1\nkind: Config\n")
            kubeconfig_path = f.name
        monkeypatch.setenv("KUBECONFIG", kubeconfig_path)
        create_response = client.post("/grants", json={"cluster_name": "grant-id-test-cluster", "role": "view"}, headers=auth_headers)
        assert create_response.status_code == 201
        grant_id = create_response.json()["id"]
        os.unlink(kubeconfig_path)
        audit_response = client.get("/audit", headers=auth_headers)
        logs = audit_response.json()
        created_entry = next((log for log in logs if log["action"] == "created"), None)
        assert created_entry is not None
        assert created_entry["grant_id"] == grant_id


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
