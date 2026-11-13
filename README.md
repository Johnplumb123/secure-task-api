# Secure Task API

![CI](https://github.com/Johnplumb123/secure-task-api/actions/workflows/ci.yml/badge.svg)

A REST API for managing tasks, built with **FastAPI**. It has JWT authentication, per-user access control, a 27-test pytest suite and a CI pipeline that tests, security-scans and builds a Docker image on every push.

The functionality is deliberately simple (a task tracker). The focus is on building it the way a production service should be built, and on **proving its security controls with tests**, including tests for real attack techniques such as IDOR, JWT `alg: none` and forged signatures.

## Tech stack

FastAPI · SQLModel (SQLAlchemy + Pydantic) · SQLite · PyJWT · bcrypt · pytest · Docker · GitHub Actions · Bandit · pip-audit

## Quick start

```bash
pip install -r requirements-dev.txt
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
uvicorn app.main:app --reload
```

Open **http://127.0.0.1:8000/docs** for interactive Swagger documentation. Click *Authorize* to log in and try every endpoint.

With Docker:

```bash
docker build -t secure-task-api .
docker run -p 8000:8000 -e SECRET_KEY=your-long-random-key secure-task-api
```

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/auth/register` | – | Create an account |
| POST | `/auth/login` | – | Get a JWT access token (OAuth2 password flow) |
| GET | `/auth/me` | ✅ | Current user |
| POST | `/tasks` | ✅ | Create a task |
| GET | `/tasks?status_filter=&limit=&offset=` | ✅ | List your tasks (paginated) |
| GET | `/tasks/{id}` | ✅ | Get one task |
| PATCH | `/tasks/{id}` | ✅ | Update a task (partial) |
| DELETE | `/tasks/{id}` | ✅ | Delete a task |
| GET | `/health` | – | Health check |

## Security design

| Threat | Control | Tested by |
|---|---|---|
| **IDOR** (OWASP A01): reading or editing other users' data by changing an ID | Every task query is scoped to the token's user; `get_owned_task()` is the single access check | `test_cannot_read/update/delete_another_users_task` |
| **ID enumeration** | Other users' tasks return **404, not 403**, so existing and missing IDs look the same | `test_existing_and_missing_ids_look_the_same_to_other_users` |
| **Mass assignment** | `owner_id` comes from the token, never the request body; input schemas have no `owner_id` field | `test_owner_id_in_body_is_ignored` |
| **JWT `alg: none` / algorithm confusion** | `jwt.decode` pins `algorithms=["HS256"]` | `test_alg_none_token_rejected` |
| **Forged / expired tokens** | Signature check; `exp` and `sub` claims are required | `test_token_signed_with_wrong_key_rejected`, `test_expired_token_rejected`, `test_token_without_expiry_rejected` |
| **Username enumeration** | Same error message for unknown user and wrong password, and a dummy bcrypt check so response times match | `test_wrong_password_and_unknown_user_give_identical_errors` |
| **Password storage** | bcrypt with per-password salt; response schemas have no password field | `test_register_does_not_return_password` |
| **Input abuse** | Pydantic validation on lengths, username characters and status enum; pagination capped at 100 | `test_invalid_input_rejected`, `test_pagination_limit_is_capped` |
| **Long-password DoS / crash** | Passwords truncated to bcrypt's 72-byte limit before hashing | `test_very_long_password_does_not_crash_login` |
| **Clickjacking / MIME sniffing / caching of sensitive data** | Security headers middleware | `test_security_headers_present` |
| **Container breakout impact** | Docker image runs as a non-root user | – |
| **Vulnerable code or dependencies** | Bandit (static analysis) and pip-audit (known CVEs) run in CI | CI `security-scan` job |

## Tests

```bash
pytest -v
```

Each test gets a fresh in-memory SQLite database through FastAPI dependency overrides, so tests are isolated and run in seconds.

## CI pipeline

On every push, GitHub Actions runs three jobs:
1. **test**: the full pytest suite
2. **security-scan**: Bandit static analysis and pip-audit for dependencies with known vulnerabilities
3. **docker**: builds the image, starts a container and checks `/health` responds

## Project structure

```
app/
  main.py       # routes + security headers middleware
  security.py   # password hashing, JWT creation/validation, current-user dependency
  models.py     # database tables and request/response schemas
  db.py         # database engine and session
  config.py     # settings from environment variables
tests/
  conftest.py   # test client, in-memory DB, user fixtures
  test_auth.py  # auth + JWT attack tests
  test_tasks.py # CRUD + access-control tests
```

## What I'd add next

- Rate limiting on `/auth/login` to slow down brute-force attacks
- Refresh tokens and token revocation (logout)
- PostgreSQL with Alembic migrations instead of SQLite
- Role-based access (e.g. admin users)
