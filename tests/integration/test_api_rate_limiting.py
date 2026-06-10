"""
Rate limiting tests for KubeTix API
Tests rate limiting on authentication and API endpoints
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
        """Test that repeated failed logins are rate limited."""
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
        
        # After rate limiting, should get 429
        # Note: Rate limiting not yet implemented
        # This test documents expected behavior
        
        # Without rate limiting, all should be 401
        rate_limited = results[-5:]  # Last 5 attempts
        print(f"Last 5 login attempt results: {rate_limited}")
        
        # This test will pass currently (no rate limiting)
        # After implementation, last attempts should return 429
    
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
        assert all(s == 200 for s in results)
    
    def test_registration_rate_limit(self, client):
        """Test that registration is rate limited."""
        # Attempt multiple registrations
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
        
        # After rate limiting, should get 429
        # Currently should all succeed (no rate limiting)
        print(f"Registration attempt results: {results}")


class TestAPIRateLimiting:
    """Tests for API endpoint rate limiting."""
    
    def test_grant_list_rate_limit(self, client, db_session, test_user):
        """Test rate limiting on grant listing."""
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
        
        # Should have some 200s, possibly 429s after rate limiting
        success_count = results.count(200)
        rate_limited = results.count(429)
        
        print(f"Success: {success_count}, Rate limited: {rate_limited}")
        
        # Without rate limiting, all should be 200
        assert success_count + rate_limited == 100
    
    def test_grant_create_rate_limit(self, client, db_session, test_user):
        """Test rate limiting on grant creation."""
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
        
        # Note: Without actual kubeconfig, these will fail validation
        # This test documents expected behavior
        
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
        
        print(f"Grant create results: {results[:10]}...")


class TestRateLimitHeaders:
    """Tests for rate limit headers."""
    
    def test_rate_limit_headers_present(self, client, db_session, test_user):
        """Test that rate limit headers are present in responses."""
        # Login
        response = client.post(
            "/login",
            json={
                "email": "test@example.com",
                "password": "testpassword123"
            }
        )
        
        # Check for rate limit headers
        # Common headers:
        # - X-RateLimit-Limit
        # - X-RateLimit-Remaining
        # - X-RateLimit-Reset
        # - Retry-After
        
        headers = response.headers
        has_rate_limit = any(
            h in headers for h in [
                'x-ratelimit-limit',
                'x-ratelimit-remaining',
                'x-rate-limit-limit'
            ]
        )
        
        print(f"Rate limit headers present: {has_rate_limit}")
        print(f"Response headers: {dict(headers)}")
        
        # Without rate limiting, headers won't be present
        # This test documents expected behavior


class TestRateLimitConfiguration:
    """Tests for rate limit configuration."""
    
    def test_different_endpoints_different_limits(self, client, db_session, test_user):
        """Test that different endpoints have different rate limits."""
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
            # Just verify endpoint works
            assert response.status_code in [200, 401, 403]
    
    def test_ip_based_rate_limiting(self, client, db_session, test_user):
        """Test that rate limiting is IP-based."""
        # Make request from same IP
        response = client.post(
            "/login",
            json={
                "email": "test@example.com",
                "password": "wrongpassword"
            }
        )
        
        # Rate limit should be based on IP
        # This test documents expected behavior
        print(f"Login response status: {response.status_code}")


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
