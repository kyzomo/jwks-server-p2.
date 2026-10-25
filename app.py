"""
app.py

Name: Ananiya Getachew
EUID: aag0447

JWKS server (Project 2) built with Flask. Private keys are stored in a
SQLite database (see keys.py).

Routes:
  GET  /.well-known/jwks.json  -> public keys for every unexpired key in
                                   the database
  POST /auth                   -> hands back a signed JWT (no real login
                                   check, per assignment instructions)
                                   add ?expired to get a token signed with
                                   an expired key from the database

Run with:  python app.py
Server listens on port 8080.
"""

import base64
import time

import jwt
from flask import Flask, jsonify, request

import keys

app = Flask(__name__)


def int_to_base64url(num):
    """Turn an integer into the base64url string format a JWK needs."""
    num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder="big")
    b64 = base64.urlsafe_b64encode(num_bytes)
    return b64.rstrip(b"=").decode("ascii")


def build_jwk(kid, pem):
    """Build one JWK entry (public part only) from a row in the DB."""
    n, e = keys.get_public_numbers(pem)
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": str(kid),
        "n": int_to_base64url(n),
        "e": int_to_base64url(e),
    }


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    keys.ensure_keys()
    jwk_list = []
    for kid, pem in keys.get_valid_keys():
        jwk_list.append(build_jwk(kid, pem))
    return jsonify({"keys": jwk_list})


@app.route("/auth", methods=["POST"])
def auth():
    # mock authentication: the body (Basic auth or JSON) is not checked
    keys.ensure_keys()
    use_expired = "expired" in request.args
    kid, pem = keys.get_signing_key(use_expired)

    now = int(time.time())
    if use_expired:
        exp_time = now - 3600
    else:
        exp_time = now + 3600

    payload = {"sub": "fake-user", "iat": now, "exp": exp_time}

    token = jwt.encode(
        payload,
        pem,
        algorithm="RS256",
        headers={"kid": str(kid)},
    )

    return jsonify({"token": token})


if __name__ == "__main__":
    # make the DB file (and the starting keys) before taking requests
    keys.ensure_keys()
    app.run(host="0.0.0.0", port=8080)
