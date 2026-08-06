# KubeTix - Agent Guidelines

## Project Overview

KubeTix is a tool for sharing temporary, time-limited Kubernetes access with your team. No more permanent admin credentials or messy kubeconfig sharing.

### What it does

- Generates kubeconfig access with automatic expiry (1h, 4h, 24h, or custom)
- Encrypts kubeconfigs at rest with Fernet (AES-128-CBC)
- Tracks an audit log of all access
- Supports instant revocation
- Provides role-based access control (view/edit/admin) and namespace scoping

## Architecture

The project has three main components:

| Component | Location | Tech | Purpose |
|-----------|----------|------|---------|
| CLI Tool | `kc-share.py` | Python 3, stdlib + cryptography | Generate, list, download, and revoke temporary kubeconfig grants |
| Backend API | `kubetix-api/main.py` | FastAPI, SQLAlchemy, SQLite/PostgreSQL | REST API with auth (JWT + SSO/OIDC), grant management, teams |
| Web UI | `kubetix-web/` | Next.js 14, React 19, Tailwind CSS | Dashboard for creating and managing grants |

There's also a Helm chart in `charts/kubetix/` for Kubernetes deployment.

## Project Structure

```
├── kc-share.py              # CLI tool (main entry point)
├── test_kc_share.py         # Unit tests (pytest-style, stdlib unittest)
├── test_integration.py      # Integration tests
├── run_tests.sh             # Test runner script
├── requirements.txt         # Python dependencies
├── pytest.ini               # Pytest configuration
├── Dockerfile               # CLI tool container image
├── docker-compose.yml       # Docker Compose for local dev
│
├── kubetix-api/             # FastAPI backend
│   ├── main.py              # API application (routes, models, auth)
│   ├── requirements.txt     # API dependencies
│   └── Dockerfile
│
├── kubetix-web/             # Next.js web dashboard
│   ├── app/                 # App Router pages
│   ├── package.json
│   └── tailwind.config.js
│
├── charts/kubetix/          # Helm chart for K8s deployment
└── tests/                   # Additional test suites
    ├── unit/                # API unit tests (auth, grants, teams, OIDC)
    ├── integration/
    └── e2e/
```

## Running Locally

### CLI Tool

```bash
pip install -r requirements.txt
python kc-share.py create --cluster prod --role edit --expiry 4
python kc-share.py list
python kc-share.py download <grant-id>
python kc-share.py revoke <grant-id>
```

Data is stored in `~/.kc-share/`. Set `KC_SHARE_KEY` env var to use a custom encryption key.

### Backend API

```bash
cd kubetix-api
pip install -r requirements.txt
uvicorn main:app --reload
```

API runs on `http://localhost:8000`.

**First-time admin setup:** Set `INITIAL_ADMIN_PASSWORD` as an environment variable before starting the API. The API creates one admin account (`admin@kubetix.local`) with that password on first startup, then never exposes or logs it. Never bake credentials into code or documentation.

### Web UI

```bash
cd kubetix-web
npm install
npm run dev
```

Visits `http://localhost:3000`.

### Docker Compose (all services)

```bash
docker-compose up -d
```

## Testing

```bash
# Run all tests
./run_tests.sh

# Unit tests only
python3 test_kc_share.py -v

# Integration tests only
python3 test_integration.py -v

# API tests
pytest tests/unit/ -v
```

The test suite covers: encryption, database operations, grant lifecycle, expiry handling, CLI commands, edge cases, security, API auth, grants, teams, and OIDC.

## Key Implementation Details

### Data Storage

- **CLI**: SQLite database at `~/.kc-share/db.sqlite` with `grants` and `audit_log` tables
- **API**: SQLAlchemy models (User, Team, TeamMember, Grant, AuditLog) backed by SQLite or PostgreSQL

### Encryption

- Fernet (AES-128-CBC) for kubeconfig encryption in both CLI and API
- CLI key management: auto-generated on first run, persisted in `~/.kc-share/config.json`, or overridden via `KC_SHARE_KEY` env var
- API key management: set `KUBECONFIG_ENCRYPTION_KEY` env var; generates an ephemeral key at startup if unset (with warning — existing grants will fail to decrypt after restart)

### Authentication (API)

- JWT tokens (HS256, 7-day expiry)
- Password hashing with bcrypt via passlib
- SSO/OIDC endpoints scaffolded for Google, GitHub, Okta, Azure AD, and Authentik/Keycloak

### Database Models

| Model | Key Fields |
|-------|-----------|
| User | id, email, hashed_password (NULL for SSO), sso_provider, sso_id, is_admin |
| Team | id, name, description, created_by |
| TeamMember | team_id, user_id, role (owner/admin/member) |
| Grant | id, user_id, cluster_name, namespace, role, encrypted_kubeconfig, expires_at, revoked |
| AuditLog | id, user_id, grant_id, action, details |

## CI/CD

- **CI** (`ci.yml`): Runs tests, linting (flake8, black), and security scanning (bandit) on push and PR
- **AI Review** (`ai-pr-review.yaml`): Automated AI review on all PRs to `main` using a reusable GitHub Action with LiteLLM-backed models


## Dependency Management

### Renovate Configuration

KubeTix uses [Renovate](https://docs.renovatebot.com/) for automated dependency updates. The configuration is in `.renovaterc.json5` and extends the shared misospace org config (`github>misospace/renovate-config`).

#### Automerge Policy

| Update Type | Auto-Merge | Notes |
|-------------|-----------|-------|
| GitHub Actions (trusted) | ✅ Yes | 1-minute release age, branch merge |
| GitHub Actions (other) | ✅ Yes | 3-day release age, branch merge |
| Python minor/patch | ✅ Yes | 3-day release age, branch merge |
| Python major | ❌ No | Requires manual review |
| Docker images | Grouped | Manual review recommended |

#### SLA for Dependency Updates

- **Automated PRs**: Renovate creates PRs on a schedule (America/Edmonton timezone). Auto-merged PRs are handled without human intervention.
- **Manual-review PRs** (major Python updates): Target resolution within **5 business days**. Label with `dependencies` for tracking.
- **Security advisories**: Priority handling — review and merge within **24 hours** of notification.


## Contributing

- Follow existing code style — Python uses stdlib + cryptography, API uses FastAPI patterns, web uses Next.js App Router
- Add tests for new features (unit + integration where applicable)
- Run `./run_tests.sh` before submitting PRs
- The AI reviewer will run automatically on PRs to `main`

### Release Process

KubeTix releases are started manually and completed by GitHub Actions. The version bump travels through a protected-branch PR.

#### Steps

1. Open **Actions → Manual Release → Run workflow** and enter a plain semver version such as `0.1.1`.
2. Follow the linked release PR. It updates the API, web package, and Helm chart versions, then auto-merges after required checks pass.
3. `Publish Release` verifies every version source, tags the merge commit, and creates the GitHub release.

If a Docker image should be published, run **Build, Publish & E2E** manually against the release tag.

#### Version convention

- Tags use plain semver (e.g. `0.1.0`, no `v` prefix)
- Release automation keeps the web package, API, and Helm chart versions aligned

#### Validation gates

The release PR must pass the protected branch's required Python, frontend, Helm, security, and E2E checks before auto-merge.

# Note: AI PR Review action version pinned to v1.0.18 for stability.
