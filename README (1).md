# JWKS Server (Project 2: SQLite)

Name: Ananiya Getachew
EUID: aag0447

A JWKS (JSON Web Key Set) server built with Flask. Private keys are
stored in a SQLite database file instead of in memory.

## Endpoints

- `GET /.well-known/jwks.json` - reads every unexpired key from the
  database and returns their public keys as a JWKS.
- `POST /auth` - reads a key from the database, signs a JWT with it, and
  returns it (no credential checking, per assignment spec). Add
  `?expired` to sign with an expired key from the database instead.

## Database

- File: `totally_not_my_privateKeys.db` (created in the folder the server
  is run from)
- Table: `keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL,
  exp INTEGER NOT NULL)`
- Private keys are saved as PKCS1 PEM bytes.
- On start (and before each request) the server makes sure there is at
  least one valid key (expires in 1 hour) and one expired key.
- All queries use `?` parameters, never string building, to prevent SQL
  injection.

## Libraries used

- Flask - web server
- PyJWT - signing/decoding JWTs
- cryptography - RSA key generation and PEM handling
- sqlite3 - database (built into Python)
- pytest / pytest-cov - testing and coverage

## Setup

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Server listens on `http://localhost:8080`.

## Test

```bash
python -m pytest tests/ --cov=. --cov-report=term-missing
```

## Gradebot

```bash
gradebot project-2 --dir="path\to\this\folder" --run="venv\Scripts\python.exe app.py" --port=8080
```
