from __future__ import annotations

# ruff: noqa: E501 -- SQL statements are intentionally kept whole.
import hashlib
import os
import secrets
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app.lab_services.compound_policy import IDENTITIES

app = FastAPI(title="Compound Lab Identity Broker")


class TokenRequest(BaseModel):
    subject: str
    device: str
    audience: str = Field(pattern=r"^(deployment|signing)$")
    scope: str
    artifact_digest: str


def _db() -> sqlite3.Connection:
    path = os.getenv("ATR_LAB_IDENTITY_DB", "/data/identity.sqlite3")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE IF NOT EXISTS tokens(fingerprint TEXT PRIMARY KEY, subject TEXT NOT NULL, device TEXT NOT NULL, audience TEXT NOT NULL, scope TEXT NOT NULL, artifact_digest TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    columns = {row[1] for row in connection.execute("PRAGMA table_info(tokens)").fetchall()}
    if "expires_at" not in columns:
        connection.execute(
            "ALTER TABLE tokens ADD COLUMN expires_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00+00:00'"
        )
    return connection


def _auth(token: str) -> None:
    if token != os.getenv("ATR_LAB_INTERNAL_TOKEN", "development-only-change-me"):
        raise HTTPException(401, "invalid lab token")


@app.get("/healthz")
async def health() -> dict[str, str]:
    with closing(_db()) as connection:
        connection.execute("SELECT 1")
    return {"status": "ok"}


@app.post("/tokens")
async def issue(payload: TokenRequest, x_atr_lab_token: str = Header(default="")) -> dict[str, str]:
    _auth(x_atr_lab_token)
    identity = IDENTITIES.get(payload.subject)
    if identity is None or identity["device"] != payload.device:
        raise HTTPException(403, "identity or device not authorized")
    opaque = secrets.token_urlsafe(32)
    token_fingerprint = hashlib.sha256(opaque.encode()).hexdigest()
    with closing(_db()) as connection:
        connection.execute(
            "INSERT INTO tokens(fingerprint,subject,device,audience,scope,artifact_digest,expires_at) VALUES(?,?,?,?,?,?,?)",
            (
                token_fingerprint,
                payload.subject,
                payload.device,
                payload.audience,
                payload.scope,
                payload.artifact_digest,
                (datetime.now(UTC) + timedelta(seconds=60)).isoformat(),
            ),
        )
        connection.commit()
    return {"token": opaque, "fingerprint": token_fingerprint, "expires_in": "60"}


@app.post("/tokens/{opaque}/consume")
async def consume(opaque: str, x_atr_lab_token: str = Header(default="")) -> dict[str, object]:
    _auth(x_atr_lab_token)
    token_fingerprint = hashlib.sha256(opaque.encode()).hexdigest()
    with closing(_db()) as connection:
        row = connection.execute(
            "SELECT * FROM tokens WHERE fingerprint=?", (token_fingerprint,)
        ).fetchone()
        if (
            row is None
            or row["used"]
            or datetime.fromisoformat(row["expires_at"]) <= datetime.now(UTC)
        ):
            return {"valid": False, "fingerprint": token_fingerprint}
        connection.execute("UPDATE tokens SET used=1 WHERE fingerprint=?", (token_fingerprint,))
        connection.commit()
    result = dict(row)
    result["valid"] = True
    return result
