from __future__ import annotations

import os

from fastapi import FastAPI, Header, HTTPException

from app.lab_services.compound_policy import ARTIFACTS, fingerprint

app = FastAPI(title="Compound Lab Artifact Registry")


def _auth(token: str) -> None:
    if token != os.getenv("ATR_LAB_INTERNAL_TOKEN", "development-only-change-me"):
        raise HTTPException(401, "invalid lab token")


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/artifacts/{artifact_id}")
async def artifact(
    artifact_id: str, x_atr_lab_token: str = Header(default="")
) -> dict[str, object]:
    _auth(x_atr_lab_token)
    record = ARTIFACTS.get(artifact_id)
    if record is None:
        raise HTTPException(404, "artifact not found")
    return {"artifact_id": artifact_id, **record, "manifest_fingerprint": fingerprint(record)}
