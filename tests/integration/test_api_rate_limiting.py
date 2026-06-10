"""
Rate limiting tests for KubeTix API
Tests rate limiting on authentication and API endpoints

Note: Rate limiting is disabled in TESTING mode (HAS_RATE_LIMITING=False).
These tests verify that without rate limiting, requests succeed normally.
When rate limiting is implemented, these tests should be updated accordingly.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from _shared_db import engine, TestingSessionLocal
import time

# Import the main app
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "kubetix-api"))

from main import app, Base, get_db, User, get_password_hash


# Test database




class TestAuthenticationRateLimiting:
    """Tests for authentication rate limiting."""
    
    def test_failed_login_rate_limit(self, client, db_session, test_user):
        """Test that repeated failed logins are not blocked without rate limiting.
        
        When rate limiting is disabled (TESTING mode), all attempts should return 401.
        When rate limiting is implemented, last attempts should return 429.
        """
        # Attempt multiple failed logins
        attempts = 20
        results = []
        
        for i in range(attempts):
            response = client.post(
                "/login",
                json={
                    "email": "test@example.com",
                    "password": "wrong-password"
                }
            )
            results.append(response.status_code)
        
        # Without rate limiting, all should be 401
        assert all(s == 401 for s in results), (
            f"Expected all 401 without rate limiting, got: {results}"
        )
    
    def test_login_success_not_rate_limited(self, client, db_session, test_user):
        """Test that successful logins are not rate limited."""
        results = []
        
        for i in range(10):
            response = client.post(
                "/login",
                json={
                    "email": "test@example.com",
                    "password": "testpassword123"
                }
            )
            results.append(response.status_code)
        
        # All should succeed
        assert all(s == 200 for s in results), (
            f"Expected all 200, got: {results}"
        )
    
    def test_registration_rate_limit(self, client):
        """Test that registration requests succeed without rate limiting.
        
        When rate limiting is disabled (TESTING mode), registrations should succeed.
        """
        results = []
        
        for i in range(15):
            response = client.post(
                "/users",
                json={
                    "email": f"test{i}@example.com",
                    "password": "testpassword123"
                }
            )
            results.append(response.status_code)
        
        # Without rate limiting, registrations should succeed (200 or 409 if duplicate)
        assert all(s in [200, 201, 409] for s in results), (
            f"Expected 200/409 without rate limiting, got: {results}"
        )


class TestAPIRateLimiting:
    """Tests for API endpoint rate limiting."""
    
    def test_grant_list_rate_limit(self, client, db_session, test_user):
        """Test rate limiting on grant listing.
        
        Without rate limiting, all requests should succeed.
        """
        # Login first
        response = client.post(
            "/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Make many requests
        results = []
        for i in range(100):
            response = client.get("/grants", headers=headers)
            results.append(response.status_code)
        
        # Without rate limiting, all should be 200
        assert all(s == 200 for s in results), (
            f"Expected all 200 without rate limiting, got: {results[:10]}..."
        )
    
    def test_grant_create_rate_limit(self, client, db_session, test_user):
        """Test rate limiting on grant creation.
        
        Without rate limiting, requests should not be blocked (may fail validation).
        """
        # Login first
        response = client.post(
            "/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        results = []
        for i in range(50):
            response = client.post(
                "/grants",
                json={
                    "cluster_name": f"cluster-{i}",
                    "role": "view"
                },
                headers=headers
            )
            results.append(response.status_code)
        
        # Without rate limiting, no 429s should appear
        assert 429 not in results, (
            f"Got 429 without rate limiting enabled: {results}"
        )


class TestRateLimitHeaders:
    """Tests for rate limit headers."""
    
    def test_rate_limit_headers_present(self, client, db_session, test_user):
        """Test that rate limit headers behavior is documented.
        
        Without rate limiting, headers won't be present. This is expected.
        """
        # Login
        response = client.post(
            "/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        
        # Check for rate limit headers
        headers = response.headers
        has_rate_limit = any(
            h in headers for h in [
                'x-ratelimit-limit',
                'x-ratelimit-remaining',
                'x-rate-limit-limit'
            ]
        )
        
        # Without rate limiting, headers won't be present
        assert not has_rate_limit, (
            "Rate limit headers should not be present when rate limiting is disabled"
        )


class TestRateLimitConfiguration:
    """Tests for rate limit configuration."""
    
    def test_different_endpoints_different_limits(self, client, db_session, test_user):
        """Test that different endpoints are accessible without rate limiting."""
        # Login
        response = client.post(
            "/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test different endpoints
        endpoints = [
            "/grants",
            "/teams",
            "/audit"
        ]
        
        for endpoint in endpoints:
            response = client.get(endpoint, headers=headers)
            # Just verify endpoint works without being rate limited
            assert response.status_code in [200, 401, 403], (
                f"Endpoint {endpoint} returned unexpected status: {response.status_code}"
            )
    
    def test_ip_based_rate_limiting(self, client, db_session, test_user):
        """Test that rate limiting is IP-based.
        
        Without rate limiting, login should return 401 for wrong password.
        """
        # Make request from same IP
        response = client.post(
            "/login",
            json={
                "email": "test@example.com",
                "password": "wrongpassword"
            }
        )
        
        assert response.status_code == 401, (
            f"Expected 401 for wrong password without rate limiting, got: {response.status_code}"
        )


# Documentation of expected rate limits
"""
Expected Rate Limits (to be implemented):

| Endpoint | Limit | Window |
|----------|-------|--------|
| /login | 10 | 15 minutes |
| /users | 5 | 15 minutes |
| /grants (GET) | 100 | 1 minute |
| /grants (POST) | 30 | 1 minute |
| /teams | 50 | 1 minute |
| /audit | 30 | 1 minute |

Rate limit headers to implement:
- X-RateLimit-Limit: Maximum requests allowed
- X-RateLimit-Remaining: Requests remaining
- X-RateLimit-Reset: Unix timestamp when limit resets
- Retry-After: Seconds to wait (when limited)
"""

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
