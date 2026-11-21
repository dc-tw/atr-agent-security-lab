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
    pause_at: str = Field(
        default="", pattern=r"^(|before_deployment|before_signing|after_signing)$"
    )


class CompoundApprovalDecision(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")
    content_fingerprint: str
    policy_version: str


class CompoundRunMutation(BaseModel):
    kind: str = Field(pattern=r"^(policy|bundle|artifact|credential|payload)$")


class CorpusReviewWrite(BaseModel):
    verdict: str = Field(pattern=r"^(true_positive|false_positive|acceptable_risk)$")
    reason: str = Field(min_length=1, max_length=500)


class FaultControlWrite(BaseModel):
    mode: str = Field(pattern=r"^(normal|timeout|status_503|truncated|slow)$")


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


@router.post("/compound-runs/{run_id}/mutations")
async def mutate_compound_run(
    run_id: str, payload: CompoundRunMutation, request: Request
) -> dict[str, Any]:
    _require_lab(request)
    await authorize(request, "admin")
    return await _proxy(request, "POST", f"/compound-runs/{run_id}/mutations", payload.model_dump())


@router.get("/review-cases/assignments")
async def get_review_assignments(request: Request) -> dict[str, Any]:
    _require_lab(request)
    await authorize(request, "operator")
    return await _proxy(request, "GET", "/review-cases/assignments")


@router.post("/review-cases/{case_id}/reviews")
async def submit_corpus_review(
    case_id: str, payload: CorpusReviewWrite, request: Request
) -> dict[str, Any]:
    _require_lab(request)
    await authorize(request, "operator")
    return await _proxy(request, "POST", f"/review-cases/{case_id}/reviews", payload.model_dump())


@router.get("/review-cases/results")
async def get_review_results(request: Request) -> dict[str, Any]:
    _require_lab(request)
    await authorize(request, "viewer")
    return await _proxy(request, "GET", "/review-cases/results")


@router.delete("/review-cases/reviews")
async def reset_corpus_reviews(request: Request) -> dict[str, Any]:
    _require_lab(request)
    await authorize(request, "admin")
    return await _proxy(request, "DELETE", "/review-cases/reviews")


@router.put("/faults/{target}")
async def set_fault(target: str, payload: FaultControlWrite, request: Request) -> dict[str, Any]:
    _require_lab(request)
    await authorize(request, "admin")
    if target not in {"deployment", "signing"}:
        raise HTTPException(404, detail="Unknown fault target")
    settings = request.app.state.settings
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.put(
                f"{settings.atr_lab_failure_proxy_url.rstrip('/')}/control/{target}",
                headers={"x-atr-lab-token": settings.atr_lab_internal_token},
                json=payload.model_dump(),
            )
    except httpx.HTTPError as exc:
        raise HTTPException(503, detail="Fault injection proxy unavailable") from exc
    if response.status_code >= 400:
        raise HTTPException(response.status_code, detail=response.text)
    return response.json()
