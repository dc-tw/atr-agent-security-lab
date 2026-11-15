from __future__ import annotations

# ruff: noqa: E501 -- SQL statements are intentionally kept whole.
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Compound Lab Signing Simulator")


class SyntheticSignature(BaseModel):
    run_id: str
    wallet_id: str
    operation: str = Field(pattern=r"^(transfer|contract_call|delegation_authorization)$")
    amount_atomic: str
    destination_fingerprint: str
    payload_fingerprint: str


def _db() -> sqlite3.Connection:
    path = os.getenv("ATR_LAB_SIGNING_DB", "/data/signing.sqlite3")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE IF NOT EXISTS signatures(signature_id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL UNIQUE, wallet_id TEXT NOT NULL, operation TEXT NOT NULL, amount_atomic TEXT NOT NULL, destination_fingerprint TEXT NOT NULL, payload_fingerprint TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
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


@app.post("/signatures")
async def sign(
    payload: SyntheticSignature, x_atr_lab_token: str = Header(default="")
) -> dict[str, object]:
    _auth(x_atr_lab_token)
    with closing(_db()) as connection:
        connection.execute(
            "INSERT INTO signatures(run_id,wallet_id,operation,amount_atomic,destination_fingerprint,payload_fingerprint) VALUES(?,?,?,?,?,?) ON CONFLICT(run_id) DO NOTHING",
            (
                payload.run_id,
                payload.wallet_id,
                payload.operation,
                payload.amount_atomic,
                payload.destination_fingerprint,
                payload.payload_fingerprint,
            ),
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM signatures WHERE run_id=?", (payload.run_id,)
        ).fetchone()
    return dict(row) if row else {}


@app.get("/signatures")
async def list_signatures(x_atr_lab_token: str = Header(default="")) -> dict[str, object]:
    _auth(x_atr_lab_token)
    with closing(_db()) as connection:
        rows = connection.execute("SELECT * FROM signatures ORDER BY signature_id").fetchall()
    return {"signatures": [dict(row) for row in rows], "count": len(rows)}
