# AI PR Review: KubeTix

## Security review conventions

KubeTix handles temporary Kubernetes access grants with encrypted kubeconfigs. Security-sensitive areas:

- **Encryption** (`kc-share.py`): Fernet (AES-128-CBC) kubeconfig encryption, key management (`KC_SHARE_KEY` env var), key generation on first run
- **Auth** (`kubetix-api/main.py`): JWT tokens (HS256), password hashing (bcrypt), SSO/OIDC endpoints for Google/GitHub/Okta/Azure AD/Authentik
- **Grant lifecycle** (`kc-share.py`, API models): expiry enforcement, revocation, encrypted storage at rest
- **Audit logging**: `audit_log` table in CLI and API models — every state-changing action should produce an audit entry
- **Database** (`KubeTix CLI`): SQLite at `~/.kc-share/db.sqlite` with `grants` and `audit_log` tables
- **API**: FastAPI with SQLAlchemy, SQLite or PostgreSQL backend

For PRs that touch these areas, call out:
- Is encryption properly applied to all kubeconfig data paths?
- Are grants immutable after creation (revocation only, no mutation)?
- Is the audit trail complete for all state changes?
- Are JWT/SSO/OIDC flows properly validated?
- Do permission checks cover edit and view-invariant roles?
- Does the change address all threat cases from the linked issue?

## Review tone

- Be direct and practical.
- Flag only real defects, regressions, or meaningful risks as blocking.
- Do not nitpick formatting, naming, or style unless it affects readability or correctness.
- Prefer `approve` or non-blocking comments for PRs that look reasonable overall.
