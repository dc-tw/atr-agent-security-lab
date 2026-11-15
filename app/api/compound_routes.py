from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.security import authorize

router = APIRouter(prefix="/v1/security/atr/lab")


class CompoundRunCreate(BaseModel):
    scenario_id: str
    control_profile: str = "protected"
    model: str = "deterministic-mock"


class CompoundApprovalDecision(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")
    content_fingerprint: str
    policy_version: str


def _require_lab(request: Request) -> None:
    if not request.app.state.settings.atr_lab_mode:
        raise HTTPException(status_code=404, detail="Not found")


async def _proxy(
    request: Request, method: str, path: str, payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    principal = await authorize(request, "viewer")
    settings = request.app.state.settings
    headers = {
        "x-atr-lab-token": settings.atr_lab_internal_token,
        "x-lab-subject": principal.subject,
        "x-lab-role": principal.role,
        "x-lab-device-id": request.headers.get("x-lab-device-id", ""),
        "x-lab-session-id": request.headers.get("x-lab-session-id", ""),
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.request(
                method,
                settings.atr_lab_compound_url.rstrip("/") + path,
                headers=headers,
                json=payload,
            )
    except httpx.HTTPError as exc:
        raise HTTPException(503, detail="Compound Lab control plane unavailable") from exc
    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        raise HTTPException(response.status_code, detail=detail)
    result = response.json()
    if not isinstance(result, dict):
        raise HTTPException(502, detail="Invalid Compound Lab response")
    return result


@router.post("/compound-runs")
async def create_compound_run(payload: CompoundRunCreate, request: Request) -> dict[str, Any]:
    _require_lab(request)
    await authorize(request, "operator")
    return await _proxy(request, "POST", "/compound-runs", payload.model_dump())


@router.get("/compound-runs")
async def list_compound_runs(request: Request) -> dict[str, Any]:
    _require_lab(request)
    return await _proxy(request, "GET", "/compound-runs")


@router.get("/compound-runs/{run_id}")
async def get_compound_run(run_id: str, request: Request) -> dict[str, Any]:
    _require_lab(request)
    return await _proxy(request, "GET", f"/compound-runs/{run_id}")


@router.get("/compound-runs/{run_id}/events")
async def get_compound_events(run_id: str, request: Request) -> dict[str, Any]:
    _require_lab(request)
    return await _proxy(request, "GET", f"/compound-runs/{run_id}/events")


@router.post("/compound-runs/{run_id}/approvals/{approval_id}")
async def decide_compound_approval(
    run_id: str, approval_id: str, payload: CompoundApprovalDecision, request: Request
) -> dict[str, Any]:
    _require_lab(request)
    await authorize(request, "operator")
    return await _proxy(
        request, "POST", f"/compound-runs/{run_id}/approvals/{approval_id}", payload.model_dump()
    )
