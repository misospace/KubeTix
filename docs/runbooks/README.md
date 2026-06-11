# Operational Runbooks

Procedures for operating KubeTix in production.

## Runbooks

| Document | Description |
|----------|-------------|
| [01-metrics-logging-error-taxonomy.md](./01-metrics-logging-error-taxonomy.md) | Logging conventions, metrics plan, and error taxonomy |
| [02-backup-restore.md](./02-backup-restore.md) | SQLite and PostgreSQL backup/restore procedures |
| [03-secret-rotation.md](./03-secret-rotation.md) | Rotating JWT keys, encryption keys, DB credentials, and OIDC secrets |
| [04-upgrade-rollback.md](./04-upgrade-rollback.md) | Helm upgrade procedures, failure scenarios, and rollback steps |

## Source

Derived from the weekly tech debt audit (2026-06-03), issue #69.
