from __future__ import annotations

# ruff: noqa: E501 -- SQL statements are intentionally kept whole.
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="ATR Lab Deployment Simulator")


class DeploymentWrite(BaseModel):
    environment: str = Field(pattern=r"^(staging|production)$")
    version: str = Field(min_length=1, max_length=128)
    change: str = Field(min_length=1, max_length=1_000)


class CompoundDeploymentWrite(BaseModel):
    run_id: str
    environment: str = Field(pattern=r"^(staging|production)$")
    artifact_id: str
    image_digest: str
    artifact_fingerprint: str


def _database_path() -> str:
    path = os.getenv("ATR_LAB_DEPLOYMENT_DB", "/data/deployments.sqlite3")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(_database_path())
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS deployments(
            deployment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            idempotency_key TEXT NOT NULL UNIQUE,
            environment TEXT NOT NULL,
            version TEXT NOT NULL,
            change_summary TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS compound_deployments(
            deployment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL UNIQUE,
            environment TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            image_digest TEXT NOT NULL,
            artifact_fingerprint TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    return connection


def _authorize(token: str) -> None:
    expected = os.getenv("ATR_LAB_INTERNAL_TOKEN", "development-only-change-me")
    if token != expected:
        raise HTTPException(status_code=401, detail="invalid lab token")


@app.get("/healthz")
async def health() -> dict[str, str]:
    with closing(_connect()) as connection:
        connection.execute("SELECT 1")
    return {"status": "ok"}


@app.post("/deployments")
async def create_deployment(
    payload: DeploymentWrite,
    idempotency_key: str = Header(min_length=16, max_length=128),
    x_atr_lab_token: str = Header(default=""),
) -> dict[str, object]:
    _authorize(x_atr_lab_token)
    with closing(_connect()) as connection:
        connection.execute(
            """
            INSERT INTO deployments(idempotency_key, environment, version, change_summary)
            VALUES(?,?,?,?) ON CONFLICT(idempotency_key) DO NOTHING
            """,
            (idempotency_key, payload.environment, payload.version, payload.change),
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM deployments WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
    return dict(row) if row else {}


@app.get("/deployments")
async def list_deployments(
    x_atr_lab_token: str = Header(default=""),
) -> dict[str, object]:
    _authorize(x_atr_lab_token)
    with closing(_connect()) as connection:
        rows = connection.execute("SELECT * FROM deployments ORDER BY deployment_id").fetchall()
    return {"deployments": [dict(row) for row in rows], "count": len(rows)}


@app.post("/compound-deployments")
async def create_compound_deployment(
    payload: CompoundDeploymentWrite,
    x_atr_lab_token: str = Header(default=""),
) -> dict[str, object]:
    _authorize(x_atr_lab_token)
    with closing(_connect()) as connection:
        connection.execute(
            "INSERT INTO compound_deployments(run_id,environment,artifact_id,image_digest,artifact_fingerprint) VALUES(?,?,?,?,?) ON CONFLICT(run_id) DO NOTHING",
            (
                payload.run_id,
                payload.environment,
                payload.artifact_id,
                payload.image_digest,
                payload.artifact_fingerprint,
            ),
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM compound_deployments WHERE run_id=?", (payload.run_id,)
        ).fetchone()
    return dict(row) if row else {}


@app.get("/compound-deployments")
async def list_compound_deployments(x_atr_lab_token: str = Header(default="")) -> dict[str, object]:
    _authorize(x_atr_lab_token)
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT * FROM compound_deployments ORDER BY deployment_id"
        ).fetchall()
    return {"deployments": [dict(row) for row in rows], "count": len(rows)}
