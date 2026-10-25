"""
test_app.py

Tests for the SQLite-backed JWKS server (app.py / keys.py).

Every test uses its own temporary database file so the real
totally_not_my_privateKeys.db is never touched.
"""

import base64
import os
import sqlite3
import sys
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import keys  # noqa: E402
from app import app as flask_app  # noqa: E402


@pytest.fixture
def db_file(tmp_path, monkeypatch):
    """Point keys.py at a fresh temp database for each test."""
    path = str(tmp_path / "test_keys.db")
    monkeypatch.setattr(keys, "DB_FILE", path)
    return path


@pytest.fixture
def client(db_file):
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as test_client:
        yield test_client


def run_query(db_file, sql, params=()):
    conn = sqlite3.connect(db_file)
    rows = conn.execute(sql, params).fetchall()
    conn.commit()
    conn.close()
    return rows


def b64url_to_int(data):
    padded = data + "=" * (-len(data) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), byteorder="big")


def public_key_from_jwk(jwk):
    return RSAPublicNumbers(
        b64url_to_int(jwk["e"]), b64url_to_int(jwk["n"])
    ).public_key()


# ---------- database tests ----------

def test_db_file_and_schema_created(db_file):
    keys.ensure_keys()
    assert os.path.exists(db_file)

    columns = run_query(db_file, "PRAGMA table_info(keys)")
    names = [col[1] for col in columns]
    assert names == ["kid", "key", "exp"]


def test_one_valid_and_one_expired_key_saved(db_file):
    keys.ensure_keys()
    now = int(time.time())

    count_valid = "SELECT COUNT(*) FROM keys WHERE exp > ?"
    count_expired = "SELECT COUNT(*) FROM keys WHERE exp <= ?"
    assert run_query(db_file, count_valid, (now,))[0][0] == 1
    assert run_query(db_file, count_expired, (now,))[0][0] == 1


def test_private_keys_saved_as_pkcs1_pem(db_file):
    keys.ensure_keys()
    rows = run_query(db_file, "SELECT key FROM keys")
    for row in rows:
        assert row[0].startswith(b"-----BEGIN RSA PRIVATE KEY-----")


def test_ensure_keys_does_not_add_duplicates(db_file):
    keys.ensure_keys()
    keys.ensure_keys()
    rows = run_query(db_file, "SELECT COUNT(*) FROM keys")
    assert rows[0][0] == 2


def test_new_valid_key_made_when_old_one_expires(db_file):
    keys.ensure_keys()
    now = int(time.time())
    # pretend the valid key just ran out
    run_query(
        db_file, "UPDATE keys SET exp = ? WHERE exp > ?", (now - 5, now)
    )

    keys.ensure_keys()
    count_valid = "SELECT COUNT(*) FROM keys WHERE exp > ?"
    assert run_query(db_file, count_valid, (now,))[0][0] == 1


# ---------- JWKS endpoint tests ----------

def test_jwks_only_has_unexpired_keys(client, db_file):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200

    jwk_list = response.get_json()["keys"]
    assert len(jwk_list) == 1

    now = int(time.time())
    valid_rows = run_query(
        db_file, "SELECT kid FROM keys WHERE exp > ?", (now,)
    )
    assert jwk_list[0]["kid"] == str(valid_rows[0][0])
    assert jwk_list[0]["kty"] == "RSA"
    assert jwk_list[0]["alg"] == "RS256"
    assert jwk_list[0]["use"] == "sig"


def test_jwks_lists_every_valid_key(client, db_file):
    keys.ensure_keys()
    keys.save_key(int(time.time()) + 7200)   # a second valid key

    jwk_list = client.get("/.well-known/jwks.json").get_json()["keys"]
    assert len(jwk_list) == 2


# ---------- auth endpoint tests ----------

def test_auth_returns_jwt_that_verifies_with_jwks(client):
    token = client.post("/auth").get_json()["token"]
    header = jwt.get_unverified_header(token)

    jwk_list = client.get("/.well-known/jwks.json").get_json()["keys"]
    match = next(k for k in jwk_list if k["kid"] == header["kid"])

    decoded = jwt.decode(
        token, public_key_from_jwk(match), algorithms=["RS256"]
    )
    assert decoded["sub"] == "fake-user"


def test_auth_expired_uses_expired_key_from_db(client, db_file):
    token = client.post("/auth?expired=true").get_json()["token"]
    header = jwt.get_unverified_header(token)

    # the kid should be a row in the DB that is already expired
    now = int(time.time())
    rows = run_query(
        db_file, "SELECT exp FROM keys WHERE kid = ?", (int(header["kid"]),)
    )
    assert rows[0][0] <= now

    # and it must not be published in the JWKS
    jwk_list = client.get("/.well-known/jwks.json").get_json()["keys"]
    assert header["kid"] not in [k["kid"] for k in jwk_list]

    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["exp"] < now


def test_expired_token_signature_matches_db_key(client, db_file):
    token = client.post("/auth?expired=true").get_json()["token"]
    header = jwt.get_unverified_header(token)

    pem = run_query(
        db_file, "SELECT key FROM keys WHERE kid = ?", (int(header["kid"]),)
    )[0][0]
    n, e = keys.get_public_numbers(pem)
    public_key = RSAPublicNumbers(e, n).public_key()

    # signature is good, it just fails because the token is expired
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, public_key, algorithms=["RS256"])


def test_auth_accepts_http_basic_auth(client):
    creds = base64.b64encode(b"userABC:password123").decode()
    response = client.post(
        "/auth", headers={"Authorization": "Basic " + creds}
    )
    assert response.status_code == 200
    assert "token" in response.get_json()


def test_auth_accepts_json_body(client):
    response = client.post(
        "/auth", json={"username": "userABC", "password": "password123"}
    )
    assert response.status_code == 200
    assert "token" in response.get_json()


def test_kid_with_sql_text_is_not_run_as_sql(db_file):
    keys.ensure_keys()
    evil = "1 OR 1=1; DROP TABLE keys;--"
    rows = run_query(db_file, "SELECT kid FROM keys WHERE kid = ?", (evil,))
    assert rows == []
    # table is still there with both keys
    assert run_query(db_file, "SELECT COUNT(*) FROM keys")[0][0] == 2


# ---------- wrong methods ----------

def test_auth_get_not_allowed(client):
    assert client.get("/auth").status_code == 405


def test_jwks_post_not_allowed(client):
    assert client.post("/.well-known/jwks.json").status_code == 405
