"""Authentication tests, including common JWT attacks."""
from datetime import timedelta

import jwt

from app import config
from app.security import create_access_token


def test_register_does_not_return_password(client):
    r = client.post("/auth/register", json={"username": "Alice", "password": "correct-horse-1"})
    assert r.status_code == 201
    body = r.json()
    assert body["username"] == "alice"  # usernames are normalised to lowercase
    assert "password" not in body and "hashed_password" not in body


def test_duplicate_username_rejected(client):
    client.post("/auth/register", json={"username": "alice", "password": "correct-horse-1"})
    r = client.post("/auth/register", json={"username": "ALICE", "password": "another-pass-1"})
    assert r.status_code == 409


def test_weak_password_rejected(client):
    r = client.post("/auth/register", json={"username": "alice", "password": "short"})
    assert r.status_code == 422


def test_invalid_username_rejected(client):
    r = client.post("/auth/register", json={"username": "<script>", "password": "correct-horse-1"})
    assert r.status_code == 422


def test_login_and_me(client, alice):
    r = client.get("/auth/me", headers=alice)
    assert r.status_code == 200
    assert r.json()["username"] == "alice"


def test_wrong_password_and_unknown_user_give_identical_errors(client, alice):
    wrong_pw = client.post("/auth/login", data={"username": "alice", "password": "nope-nope-nope"})
    no_user = client.post("/auth/login", data={"username": "nobody", "password": "nope-nope-nope"})
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()  # no username enumeration


def test_very_long_password_does_not_crash_login(client, alice):
    r = client.post("/auth/login", data={"username": "alice", "password": "x" * 5000})
    assert r.status_code == 401


def test_no_token_rejected(client):
    assert client.get("/tasks").status_code == 401


def test_garbage_token_rejected(client):
    r = client.get("/tasks", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401


def test_expired_token_rejected(client, alice):
    me = client.get("/auth/me", headers=alice).json()
    token = create_access_token(me["id"], expires_delta=timedelta(seconds=-1))
    r = client.get("/tasks", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_token_signed_with_wrong_key_rejected(client, alice):
    me = client.get("/auth/me", headers=alice).json()
    forged = jwt.encode({"sub": str(me["id"]), "exp": 9999999999}, "attacker-controlled-key-that-is-long-enough", algorithm="HS256")
    r = client.get("/tasks", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_alg_none_token_rejected(client, alice):
    """Classic JWT attack: strip the signature and set alg to 'none'."""
    me = client.get("/auth/me", headers=alice).json()
    unsigned = jwt.encode({"sub": str(me["id"]), "exp": 9999999999}, key=None, algorithm="none")
    r = client.get("/tasks", headers={"Authorization": f"Bearer {unsigned}"})
    assert r.status_code == 401


def test_token_without_expiry_rejected(client, alice):
    me = client.get("/auth/me", headers=alice).json()
    token = jwt.encode({"sub": str(me["id"])}, config.SECRET_KEY, algorithm=config.ALGORITHM)
    r = client.get("/tasks", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_token_for_deleted_or_unknown_user_rejected(client):
    token = create_access_token(99999)
    r = client.get("/tasks", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_security_headers_present(client):
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
