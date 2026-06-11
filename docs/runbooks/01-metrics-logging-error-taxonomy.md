# Metrics, Logging & Error Taxonomy

## Overview

KubeTix is a small service with no dedicated metrics collection by default.
This runbook defines the logging conventions and error taxonomy so operators
can monitor, debug, and alert on production incidents reliably.

## Logging Conventions

### Log Levels

| Level    | When to Use                                                        |
|----------|---------------------------------------------------------------------|
| `ERROR`  | Unhandled exceptions, database failures, auth failures              |
| `WARNING`| Recoverable issues (missing config, rate limits, expired grants)    |
| `INFO`   | Request lifecycle, grant creation/revocation, admin bootstrap       |
| `DEBUG`  | Detailed tracing (development only; not for production)             |

### Structured Log Format

All API logs should use JSON format in production:

```json
{"timestamp": "2026-06-10T12:00:00Z", "level": "INFO", "component": "kubetix-api", "event": "grant.created", "user_id": "...", "grant_id": "...", "cluster": "prod"}
```

### Key Events to Log

| Event | Level | Description |
|-------|-------|-------------|
| `startup.complete` | INFO | API started successfully |
| `startup.warning` | WARNING | Missing configuration at startup |
| `grant.created` | INFO | New grant generated |
| `grant.revoked` | INFO | Grant manually revoked |
| `grant.expired` | INFO | Grant expired (background cleanup) |
| `auth.success` | INFO | Successful authentication |
| `auth.failure` | WARNING | Failed login attempt |
| `auth.token.invalid` | WARNING | JWT verification failed |
| `db.connection.failed` | ERROR | Database connection error |
| `encryption.error` | ERROR | Fernet decryption failure |
| `rate_limit.exceeded` | WARNING | Client hit rate limit |

## Metrics (Future)

KubeTix does not currently export Prometheus metrics. Recommended additions:

- `kubetix_grants_total` — total grants created (counter)
- `kubetix_grants_active` — currently active (unexpired, unrevoked) grants (gauge)
- `kubetix_auth_failures_total` — failed authentication attempts (counter)
- `kubetix_request_duration_seconds` — API request latency (histogram)
- `kubetix_db_errors_total` — database errors (counter)

## Error Taxonomy

### Authentication Errors

| Code | Scenario | Action |
|------|----------|--------|
| `AUTH_001` | Invalid password | Check credentials, verify user exists |
| `AUTH_002` | Expired JWT (7-day default) | Re-authenticate via SSO or password |
| `AUTH_003` | Invalid JWT signature | **Secret key may have changed** — see Secret Rotation runbook |
| `AUTH_004` | SSO/OIDC callback failure | Check provider configuration, token endpoint |

### Database Errors

| Code | Scenario | Action |
|------|----------|--------|
| `DB_001` | SQLite file locked | Check for concurrent writes; verify replicaCount=1 |
| `DB_002` | PostgreSQL connection refused | Check host/port/credentials; verify network policies |
| `DB_003` | Migration failure | Review migration scripts; check schema version |

### Encryption Errors

| Code | Scenario | Action |
|------|----------|--------|
| `ENC_001` | Fernet decryption failed (bad key) | Verify `KUBECONFIG_ENCRYPTION_KEY` env var matches original |
| `ENC_002` | Grant cannot be decrypted after restart | Key was regenerated at startup — see Secret Rotation runbook |

### Infrastructure Errors

| Code | Scenario | Action |
|------|----------|--------|
| `INFRA_001` | Helm upgrade invalidated JWTs | New random secret key generated — see Upgrade Rollback runbook |
| `INFRA_002` | Single replica constraint violated | Multi-replica + SQLite is unsupported; switch to PostgreSQL |

## Alerting Recommendations

| Condition | Severity | Suggested Threshold |
|-----------|----------|---------------------|
| API process down | Critical | Restart failed, no response on /health |
| Database unreachable | Critical | Connection errors > 0 in 1 minute |
| Auth failure spike | Warning | > 20 failures in 5 minutes |
| Grant decryption failures | Warning | Any occurrence — may indicate key mismatch |
| Rate limit exceeded | Info | Normal traffic pattern; no action needed |
