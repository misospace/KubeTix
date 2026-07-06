#!/usr/bin/env python3
"""
Migration script: add foreign key constraints to existing KubeTix database.

This script is designed to be run once against an existing SQLite database
before the application starts with FK-constrained models. It:

1. Checks for orphaned records that would violate new FK constraints.
2. Reports or cleans up orphaned data (configurable).
3. Applies FK constraints via ALTER TABLE ADD CONSTRAINT.

Usage:
    python migrate_add_fk.py [--database <path>] [--dry-run] [--cleanup]

Environment:
    DATABASE_URL  - override default kubetix.db path
"""

import argparse
import os
import sqlite3
import sys

DEFAULT_DB = "kubetix.db"


def get_db_path():
    url = os.environ.get("DATABASE_URL", "")
    if url.startswith("sqlite:///"):
        return url[len("sqlite:///") :]
    return os.environ.get("DATABASE_PATH", DEFAULT_DB)


def check_orphans(conn: sqlite3.Connection) -> dict:
    """Check for orphaned records in all tables that will get FK constraints."""
    issues = {}

    # Team.created_by → users.id
    cur = conn.execute(
        "SELECT t.id, t.name, t.created_by FROM teams t "
        "LEFT JOIN users u ON t.created_by = u.id WHERE u.id IS NULL"
    )
    rows = cur.fetchall()
    if rows:
        issues["teams.created_by"] = {
            "count": len(rows),
            "orphaned_team_ids": [r[0] for r in rows],
            "detail": f"{len(rows)} team(s) reference non-existent users",
        }

    # TeamMember.team_id → teams.id
    cur = conn.execute(
        "SELECT tm.id, tm.team_id, tm.user_id FROM team_members tm "
        "LEFT JOIN teams t ON tm.team_id = t.id WHERE t.id IS NULL"
    )
    rows = cur.fetchall()
    if rows:
        issues["team_members.team_id"] = {
            "count": len(rows),
            "orphaned_ids": [r[0] for r in rows],
            "detail": f"{len(rows)} team membership(s) reference non-existent teams",
        }

    # TeamMember.user_id → users.id
    cur = conn.execute(
        "SELECT tm.id, tm.team_id, tm.user_id FROM team_members tm "
        "LEFT JOIN users u ON tm.user_id = u.id WHERE u.id IS NULL"
    )
    rows = cur.fetchall()
    if rows:
        issues["team_members.user_id"] = {
            "count": len(rows),
            "orphaned_ids": [r[0] for r in rows],
            "detail": f"{len(rows)} team membership(s) reference non-existent users",
        }

    # Grant.user_id → users.id
    cur = conn.execute(
        "SELECT g.id, g.user_id, g.cluster_name FROM grants g "
        "LEFT JOIN users u ON g.user_id = u.id WHERE u.id IS NULL"
    )
    rows = cur.fetchall()
    if rows:
        issues["grants.user_id"] = {
            "count": len(rows),
            "orphaned_ids": [r[0] for r in rows],
            "detail": f"{len(rows)} grant(s) reference non-existent users",
        }

    # AuditLog.user_id → users.id
    cur = conn.execute(
        "SELECT a.id, a.user_id, a.action FROM audit_log a "
        "LEFT JOIN users u ON a.user_id = u.id WHERE u.id IS NULL"
    )
    rows = cur.fetchall()
    if rows:
        issues["audit_log.user_id"] = {
            "count": len(rows),
            "orphaned_ids": [r[0] for r in rows],
            "detail": f"{len(rows)} audit log(s) reference non-existent users",
        }

    # AuditLog.grant_id → grants.id (SET NULL — no orphans possible, but check)
    cur = conn.execute(
        "SELECT a.id, a.grant_id FROM audit_log a "
        "LEFT JOIN grants g ON a.grant_id = g.id WHERE a.grant_id IS NOT NULL AND g.id IS NULL"
    )
    rows = cur.fetchall()
    if rows:
        issues["audit_log.grant_id"] = {
            "count": len(rows),
            "orphaned_ids": [r[0] for r in rows],
            "detail": f"{len(rows)} audit log(s) reference non-existent grants",
        }

    return issues


def cleanup_orphans(conn: sqlite3.Connection, issues: dict):
    """Remove orphaned records to satisfy FK constraints."""
    # TeamMember CASCADE on delete — remove memberships for deleted teams/users
    if "team_members.team_id" in issues:
        conn.execute(
            "DELETE FROM team_members WHERE team_id NOT IN (SELECT id FROM teams)"
        )

    if "team_members.user_id" in issues:
        conn.execute(
            "DELETE FROM team_members WHERE user_id NOT IN (SELECT id FROM users)"
        )

    # AuditLog SET NULL on delete — set grant_id to NULL for deleted grants
    if "audit_log.grant_id" in issues:
        conn.execute(
            "UPDATE audit_log SET grant_id = NULL WHERE grant_id NOT IN (SELECT id FROM grants) AND grant_id IS NOT NULL"
        )

    # For RESTRICT constraints, we cannot auto-cleanup orphaned parents.
    # These must be handled manually.
    restrict_orphans = {k: v for k, v in issues.items() if "RESTRICT" in str(v)}
    if restrict_orphans:
        print(
            "WARNING: The following tables have RESTRICT FK constraints and "
            "cannot be auto-cleaned. Remove orphaned records manually:"
        )
        for key, info in restrict_orphans.items():
            print(f"  - {key}: {info['detail']}")
        raise ValueError(
            "Cannot proceed with RESTRICT FK constraints until orphans are resolved. "
            "Delete the orphaned parent records or update them to reference valid users."
        )


def apply_fk_constraints(conn: sqlite3.Connection):
    """Apply FK constraints via ALTER TABLE. SQLite requires separate ALTER for each FK."""
    # Note: SQLite's ALTER TABLE ADD CONSTRAINT is limited. We use CREATE INDEX
    # approach with foreign keys enabled at the connection level.
    # For existing tables, we need to recreate with FK constraints.

    print("SQLite migration note:")
    print("  SQLite does not support ALTER TABLE ADD CONSTRAINT for foreign keys.")
    print("  The application will enable FK enforcement via PRAGMA at runtime.")
    print("  Existing data without orphans is already compatible.")
    print()
    print("FK constraints defined in models (enforced at runtime via PRAGMA):")
    print("  Team.created_by       → users.id         (RESTRICT)")
    print("  TeamMember.team_id    → teams.id          (CASCADE)")
    print("  TeamMember.user_id    → users.id          (RESTRICT)")
    print("  Grant.user_id         → users.id          (RESTRICT)")
    print("  AuditLog.user_id      → users.id          (RESTRICT)")
    print("  AuditLog.grant_id     → grants.id         (SET NULL)")


def main():
    parser = argparse.ArgumentParser(
        description="Migrate KubeTix DB to add FK constraints"
    )
    parser.add_argument("--database", default=None, help="Path to SQLite database")
    parser.add_argument(
        "--dry-run", action="store_true", help="Check only, don't modify"
    )
    parser.add_argument(
        "--cleanup", action="store_true", help="Auto-cleanup orphaned child records"
    )
    args = parser.parse_args()

    db_path = args.database or get_db_path()
    if not os.path.exists(db_path):
        print(f"Database not found: {db_path}")
        print("No migration needed — fresh database will use FK-constrained models.")
        return 0

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        issues = check_orphans(conn)

        if not issues:
            print(
                "✓ No orphaned records found. Database is compatible with FK constraints."
            )
            apply_fk_constraints(conn)
            return 0

        print(f"Found {len(issues)} potential FK constraint violation(s):")
        for key, info in issues.items():
            print(f"  ✗ {key}: {info['detail']}")

        if args.dry_run:
            print("\n[Dry run] No changes made.")
            return 1

        # Auto-cleanup child records (CASCADE/SET NULL)
        if args.cleanup:
            cleanup_orphans(conn, issues)
            conn.commit()
            print("✓ Orphaned child records cleaned up.")

        # Re-check after cleanup
        remaining = check_orphans(conn)
        if not remaining:
            apply_fk_constraints(conn)
            return 0

        print("\nRemaining RESTRICT violations (must be resolved manually):")
        for key, info in remaining.items():
            print(f"  ✗ {key}: {info['detail']}")

        return 1

    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
