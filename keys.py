"""
keys.py

Stores the server's RSA private keys in a SQLite database file.

Every query uses "?" placeholders (parameterized queries) instead of
building SQL strings by hand, so values can never be run as SQL. This
is what protects against SQL injection.

Table (created if it doesn't exist):
    kid  - integer id, assigned by SQLite
    key  - the private key saved as PKCS1 PEM bytes
    exp  - unix timestamp when the key expires
"""

import sqlite3
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# DB file name (made in the folder the server is run from)
DB_FILE = "totally_not_my_privateKeys.db"


def get_connection():
    return sqlite3.connect(DB_FILE)


def init_db():
    """Create the keys table if it isn't there yet."""
    conn = get_connection()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS keys("
        "kid INTEGER PRIMARY KEY AUTOINCREMENT, "
        "key BLOB NOT NULL, "
        "exp INTEGER NOT NULL)"
    )
    conn.commit()
    conn.close()


def save_key(exp):
    """Make a new RSA key, save it as PEM with this exp, return its kid."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    # SQLite can't store a key object, so turn it into PKCS1 PEM bytes
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp)
    )
    conn.commit()
    kid = cursor.lastrowid
    conn.close()
    return kid


def ensure_keys():
    """
    Make sure the DB has at least one valid key and one expired key.
    Safe to call over and over, it only adds a key if one is missing.
    """
    init_db()
    now = int(time.time())

    conn = get_connection()
    valid_count = conn.execute(
        "SELECT COUNT(*) FROM keys WHERE exp > ?", (now,)
    ).fetchone()[0]
    expired_count = conn.execute(
        "SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,)
    ).fetchone()[0]
    conn.close()

    if valid_count == 0:
        save_key(now + 3600)     # expires in 1 hour
    if expired_count == 0:
        save_key(now - 3600)     # expired 1 hour ago


def get_signing_key(expired):
    """Return (kid, pem_bytes) of an expired or a valid key from the DB."""
    now = int(time.time())
    conn = get_connection()
    if expired:
        row = conn.execute(
            "SELECT kid, key FROM keys WHERE exp <= ? "
            "ORDER BY exp DESC LIMIT 1", (now,)
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT kid, key FROM keys WHERE exp > ? "
            "ORDER BY exp DESC LIMIT 1", (now,)
        ).fetchone()
    conn.close()
    return row[0], row[1]


def get_valid_keys():
    """Return a list of (kid, pem_bytes) for every unexpired key."""
    now = int(time.time())
    conn = get_connection()
    rows = conn.execute(
        "SELECT kid, key FROM keys WHERE exp > ?", (now,)
    ).fetchall()
    conn.close()
    return rows


def get_public_numbers(pem):
    """Load a PEM private key and return its public (n, e) numbers."""
    private_key = serialization.load_pem_private_key(pem, password=None)
    numbers = private_key.public_key().public_numbers()
    return numbers.n, numbers.e
