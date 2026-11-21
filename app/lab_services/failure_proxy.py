from __future__ import annotations

import asyncio
import os
from typing import Literal

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel

app = FastAPI(title="ATR Lab Failure Injection Proxy")
TARGETS = {
    "deployment": os.getenv(
        "ATR_LAB_PROXY_DEPLOYMENT_UPSTREAM", "http://deployment-simulator:8030"
    ),
    "signing": os.getenv("ATR_LAB_PROXY_SIGNING_UPSTREAM", "http://signing-simulator:8050"),
}
MODES: dict[str, str] = {name: "normal" for name in TARGETS}


class FaultWrite(BaseModel):
    mode: Literal["normal", "timeout", "status_503", "truncated", "slow"]


def _auth(token: str) -> None:
    if token != os.getenv("ATR_LAB_INTERNAL_TOKEN", "development-only-change-me"):
        raise HTTPException(401, "invalid lab token")


@app.get("/healthz")
async def health() -> dict[str, object]:
    return {"status": "ok", "targets": dict(MODES)}


@app.put("/control/{target}")
async def control(
    target: str, payload: FaultWrite, x_atr_lab_token: str = Header(default="")
) -> dict[str, str]:
    _auth(x_atr_lab_token)
    if target not in TARGETS:
        raise HTTPException(404, "unknown proxy target")
    MODES[target] = payload.mode
    return {"target": target, "mode": payload.mode}


@app.api_route("/proxy/{target}/{path:path}", methods=["GET", "POST"])
async def proxy(
    target: str,
    path: str,
    request: Request,
    x_atr_lab_token: str = Header(default=""),
) -> Response:
    _auth(x_atr_lab_token)
    if target not in TARGETS:
        raise HTTPException(404, "unknown proxy target")
    mode = MODES[target]
    if mode == "timeout":
        await asyncio.sleep(10)
    if mode == "status_503":
        return Response(status_code=503, content=b'{"error":"injected_unavailable"}')
    if mode == "truncated":
        return Response(status_code=200, media_type="application/json", content=b'{"truncated":')
    if mode == "slow":
        await asyncio.sleep(1)
    headers = {"x-atr-lab-token": x_atr_lab_token}
    if content_type := request.headers.get("content-type"):
        headers["content-type"] = content_type
    if idempotency_key := request.headers.get("idempotency-key"):
        headers["idempotency-key"] = idempotency_key
    async with httpx.AsyncClient(timeout=5) as client:
        upstream = await client.request(
            request.method,
            TARGETS[target].rstrip("/") + "/" + path,
            headers=headers,
            content=await request.body(),
        )
    return Response(
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type", "application/json"),
        content=upstream.content,
    )
