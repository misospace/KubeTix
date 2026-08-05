# KubeTix API

FastAPI backend for KubeTix - Temporary Kubernetes Access Manager.

## Features

- 🔐 JWT-based authentication
- 👥 Team management (multi-user support)
- 🔑 Role-based access control (owner, admin, member)
- 🔗 SSO support (Google, GitHub, Okta, Azure AD)
- 📊 Audit logging
- 🔒 Encrypted kubeconfig storage
- ⏰ Automatic grant expiry

## Tech Stack

- **Framework**: FastAPI
- **Database**: PostgreSQL (SQLite for development)
- **Authentication**: JWT (python-jose)
- **Password Hashing**: bcrypt (passlib)
- **ORM**: SQLAlchemy
- **Container**: Docker

## Quick Start

### Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run with SQLite (development)
uvicorn main:app --reload

# Or with PostgreSQL
export DATABASE_URL=postgresql://user:pass@localhost/kubetix
uvicorn main:app --reload
```

### Docker

```bash
# Start with PostgreSQL
docker-compose up -d

# Access API
curl http://localhost:8000/health

# Access web UI
open http://localhost:3000
```

## API Documentation

Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Endpoints

### Authentication
- `POST /users` - Register new user
- `POST /login` - Login and get JWT token
- `GET /users/me` - Get current user info
- `GET /api/v1/auth/sso/callback` - SSO callback
- `GET /auth/sso/{provider}/login` - Initiate SSO login

### Grants
- `GET /grants` - List active grants
- `POST /grants` - Create new grant
- `GET /grants/{id}/download` - Download kubeconfig
- `DELETE /grants/{id}` - Revoke grant

### Teams
- `POST /teams` - Create team
- `GET /teams` - List user's teams
- `GET /teams/{id}` - Get team details
- `POST /teams/{id}/members` - Add team member
- `DELETE /teams/{id}/members/{user_id}` - Remove member
- `GET /teams/{id}/members` - List team members

### Audit
- `GET /audit` - View audit logs (admin only)

### Health
- `GET /health` - Health check

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | Database connection string (e.g. `postgresql://user:pass@localhost/kubetix`) |
| `KUBETIX_SECRET_KEY` | Yes | Secret key used to sign JWT tokens. **Must be set** — the API will refuse to start without it. Generate one with: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `KUBECONFIG` | No | Path to kubeconfig file for cluster access |

```bash
# Generate a secure secret key
export KUBETIX_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

DATABASE_URL=postgresql://user:pass@localhost/kubetix
KUBECONFIG=/path/to/kubeconfig
```

> **⚠️ Important:** `KUBETIX_SECRET_KEY` must be a stable, persistent value. If it changes (e.g., due to regeneration on every restart), all existing JWT tokens become invalid immediately, breaking active sessions and automation. Store it in a secrets manager or environment file.

## Bootstrap Admin User

Set `INITIAL_ADMIN_PASSWORD` to create an initial admin account on first startup:

- **Email**: `admin@kubetix.local`
- **Password**: (set via `INITIAL_ADMIN_PASSWORD` env var)

When set, the API creates a default admin user with the provided password.
Omit or leave empty to skip admin creation (fail closed).

## Security

- Passwords hashed with bcrypt
- JWT tokens with 7-day expiry
- Encrypted kubeconfig storage
- Role-based access control
- Audit logging for all actions

## Testing

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest
```

## Deployment

### Production Checklist

- [ ] Change `KUBETIX_SECRET_KEY` to a secure random value
- [ ] Use PostgreSQL in production (not SQLite)
- [ ] Enable HTTPS
- [ ] Configure CORS origins
- [ ] Set up database backups
- [ ] Configure monitoring and logging
- [ ] Change default admin credentials
- [ ] Set up SSO providers (Google, GitHub, etc.)

## License

MIT License
