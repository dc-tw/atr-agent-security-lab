from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator

from app.core.atr_policy import default_atr_policy
from app.core.atr_rules import load_rule_bundle, rule_bundle_manifest
from app.core.security import authorize
from app.core.siem_export import encrypt_sink_secret
from app.core.threat_detection import SEVERITY_RANK

router = APIRouter(prefix="/v1/security/atr", tags=["security", "atr"])

Severity = Literal["informational", "low", "medium", "high", "critical"]
ATRAction = Literal["detect", "block", "quarantine", "require_approval"]


class ATRPolicyWrite(BaseModel):
    mode: Literal["detection_only", "blocking"] = "detection_only"
    minimum_severity: Severity = "medium"
    block_severity: Literal["low", "medium", "high", "critical"] = "high"
    action_map: dict[Severity, ATRAction] = Field(
        default_factory=lambda: {
            "informational": "detect",
            "low": "detect",
            "medium": "detect",
            "high": "block",
            "critical": "quarantine",
        }
    )
    enabled_rule_ids: list[str] = Field(default_factory=list, max_length=2_000)
    excluded_rule_ids: list[str] = Field(default_factory=list, max_length=2_000)

    @field_validator("enabled_rule_ids", "excluded_rule_ids")
    @classmethod
    def unique_rule_ids(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value if item.strip()]
        if any(len(item) > 128 for item in normalized):
            raise ValueError("ATR rule IDs must not exceed 128 characters")
        if len(set(normalized)) != len(normalized):
            raise ValueError("ATR rule IDs must be unique")
        return normalized

    @field_validator("action_map")
    @classmethod
    def complete_action_map(cls, value: dict[Severity, ATRAction]) -> dict[Severity, ATRAction]:
        missing = set(SEVERITY_RANK) - set(value)
        if missing:
            raise ValueError(f"action_map is missing severities: {sorted(missing)}")
        return value


class ATRExemptionWrite(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
    valid_for_minutes: int = Field(default=60, ge=1, le=10_080)


class ATRExportSinkWrite(BaseModel):
    sink_type: Literal["webhook", "jsonl"]
    url: HttpUrl | None = None
    secret: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def validate_sink(self) -> ATRExportSinkWrite:
        if self.sink_type == "webhook" and (self.url is None or not self.secret):
            raise ValueError("webhook sinks require url and secret")
        if self.sink_type == "jsonl" and (self.url is not None or self.secret):
            raise ValueError("jsonl sinks use the server-configured path")
        return self


def _runtime(request: Request):
    runtime = request.app.state.redis
    if runtime is None or not hasattr(runtime, "get_active_atr_policy"):
        raise HTTPException(
            status_code=503,
            detail="ATR policy management requires PostgreSQL",
        )
    return runtime


def _default_policy(request: Request, tenant_id: str) -> dict[str, Any]:
    return default_atr_policy(request.app.state.settings, tenant_id)


@router.get("/policies/active")
async def get_active_policy(request: Request) -> dict[str, Any]:
    principal = await authorize(request, "viewer")
    policy = await _runtime(request).get_active_atr_policy(principal.tenant_id)
    return policy or _default_policy(request, principal.tenant_id)


@router.get("/policies")
async def list_policy_versions(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
) -> dict[str, Any]:
    principal = await authorize(request, "admin")
    policies = await _runtime(request).list_atr_policy_versions(principal.tenant_id, limit=limit)
    return {"policies": policies, "count": len(policies)}


@router.put("/policies/active")
async def replace_active_policy(payload: ATRPolicyWrite, request: Request) -> dict[str, Any]:
    principal = await authorize(request, "admin")
    runtime = _runtime(request)
    policy = await runtime.create_atr_policy(
        principal.tenant_id,
        payload.model_dump(),
        created_by=principal.subject,
    )
    await runtime.append_audit(
        principal.tenant_id,
        {
            "action": "atr.policy.activate",
            "status": "completed",
            "subject": principal.subject,
            "policy_id": policy["policy_id"],
            "policy_version": policy["version"],
            "mode": policy["mode"],
        },
    )
    return policy


@router.post("/policies/{version}/rollback")
async def rollback_policy(version: int, request: Request) -> dict[str, Any]:
    principal = await authorize(request, "admin")
    runtime = _runtime(request)
    policy = await runtime.rollback_atr_policy(
        principal.tenant_id, version, created_by=principal.subject
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="ATR policy version not found")
    await runtime.append_audit(
        principal.tenant_id,
        {
            "action": "atr.policy.rollback",
            "status": "completed",
            "subject": principal.subject,
            "source_version": version,
            "policy_id": policy["policy_id"],
            "policy_version": policy["version"],
        },
    )
    return policy


@router.get("/receipts")
async def list_receipts(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
) -> dict[str, Any]:
    principal = await authorize(request, "admin")
    receipts = await _runtime(request).list_enforcement_receipts(principal.tenant_id, limit=limit)
    return {"receipts": receipts, "count": len(receipts)}


@router.get("/receipts/verify")
async def verify_receipts(request: Request) -> dict[str, Any]:
    principal = await authorize(request, "admin")
    return await _runtime(request).verify_enforcement_receipts(principal.tenant_id)


@router.post("/findings/{finding_id}/exempt")
async def create_one_time_exemption(
    finding_id: str, payload: ATRExemptionWrite, request: Request
) -> dict[str, Any]:
    principal = await authorize(request, "admin")
    runtime = _runtime(request)
    exemption = await runtime.create_atr_exemption(
        principal.tenant_id,
        finding_id,
        created_by=principal.subject,
        expires_at=datetime.now(UTC) + timedelta(minutes=payload.valid_for_minutes),
    )
    if exemption is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found or has no privacy-safe content fingerprint",
        )
    await runtime.append_audit(
        principal.tenant_id,
        {
            "action": "atr.exemption.create",
            "status": "completed",
            "subject": principal.subject,
            "finding_id": finding_id,
            "exemption_id": exemption["exemption_id"],
            "remaining_uses": 1,
            "expires_at": exemption["expires_at"],
            "reason": payload.reason,
        },
    )
    return exemption


@router.post("/rules/reload")
async def reload_rules(request: Request) -> dict[str, Any]:
    principal = await authorize(request, "admin")
    runtime = _runtime(request)
    try:
        detector, manifest = load_rule_bundle(request.app.state.settings)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    bundle = await runtime.activate_atr_rule_bundle(manifest, activated_by=principal.subject)
    request.app.state.threat_detector = detector
    await runtime.append_audit(
        principal.tenant_id,
        {
            "action": "atr.rules.reload",
            "status": "completed",
            "subject": principal.subject,
            "bundle_id": bundle["bundle_id"],
            "bundle_version": bundle["version"],
            "checksum": bundle["checksum"],
            "rule_count": bundle["rule_count"],
        },
    )
    return bundle


@router.get("/rules/bundles")
async def list_rule_bundles(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
) -> dict[str, Any]:
    await authorize(request, "admin")
    bundles = await _runtime(request).list_atr_rule_bundles(limit=limit)
    return {"bundles": bundles, "count": len(bundles)}


@router.get("/rules")
async def list_rules(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=2_000)] = 1_000,
) -> dict[str, Any]:
    await authorize(request, "viewer")
    runtime = _runtime(request)
    active = await runtime.get_active_atr_rule_bundle()
    if active is None:
        manifest = rule_bundle_manifest(
            request.app.state.threat_detector,
            request.app.state.settings.atr_rules_dir,
        )
        return {
            "bundle": {key: value for key, value in manifest.items() if key != "rules"},
            "rules": manifest["rules"][:limit],
            "count": min(limit, len(manifest["rules"])),
        }
    rules = await runtime.list_atr_rules(active["bundle_id"], limit=limit)
    return {"bundle": active, "rules": rules, "count": len(rules)}


@router.post("/rules/bundles/{bundle_id}/rollback")
async def rollback_rule_bundle(bundle_id: str, request: Request) -> dict[str, Any]:
    principal = await authorize(request, "admin")
    runtime = _runtime(request)
    bundle = await runtime.get_atr_rule_bundle(bundle_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="ATR rule bundle not found")
    source_path = "" if bundle["source_path"] == "pyatr://default" else bundle["source_path"]
    try:
        detector, manifest = load_rule_bundle(request.app.state.settings, source_path)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if manifest["checksum"] != bundle["checksum"]:
        raise HTTPException(
            status_code=409,
            detail="Mounted rule bundle changed; checksum no longer matches rollback target",
        )
    activated = await runtime.activate_atr_rule_bundle(manifest, activated_by=principal.subject)
    request.app.state.threat_detector = detector
    await runtime.append_audit(
        principal.tenant_id,
        {
            "action": "atr.rules.rollback",
            "status": "completed",
            "subject": principal.subject,
            "bundle_id": activated["bundle_id"],
            "checksum": activated["checksum"],
        },
    )
    return activated


@router.post("/exports/sinks")
async def create_export_sink(payload: ATRExportSinkWrite, request: Request) -> dict[str, Any]:
    principal = await authorize(request, "admin")
    settings = request.app.state.settings
    if (
        payload.sink_type == "webhook"
        and payload.url
        and payload.url.scheme != "https"
        and settings.app_env != "development"
    ):
        raise HTTPException(status_code=422, detail="Production webhooks require HTTPS")
    if payload.sink_type == "webhook" and payload.url and settings.app_env != "development":
        hostname = (payload.url.host or "").lower()
        if hostname not in settings.atr_webhook_allowed_hosts:
            raise HTTPException(
                status_code=422,
                detail="Webhook hostname is not in ATR_WEBHOOK_ALLOWED_HOSTS",
            )
    url = str(payload.url) if payload.url else settings.atr_jsonl_path
    encrypted_secret = encrypt_sink_secret(payload.secret, settings.atr_export_encryption_secret)
    runtime = _runtime(request)
    sink = await runtime.create_export_sink(
        principal.tenant_id,
        sink_type=payload.sink_type,
        url=url,
        encrypted_secret=encrypted_secret,
        created_by=principal.subject,
    )
    await runtime.append_audit(
        principal.tenant_id,
        {
            "action": "atr.export_sink.create",
            "status": "completed",
            "subject": principal.subject,
            "sink_id": sink["sink_id"],
            "sink_type": sink["sink_type"],
        },
    )
    return sink


@router.get("/exports/sinks")
async def list_export_sinks(request: Request) -> dict[str, Any]:
    principal = await authorize(request, "admin")
    sinks = await _runtime(request).list_export_sinks(principal.tenant_id)
    return {"sinks": sinks, "count": len(sinks)}


@router.delete("/exports/sinks/{sink_id}")
async def delete_export_sink(sink_id: str, request: Request) -> dict[str, Any]:
    principal = await authorize(request, "admin")
    runtime = _runtime(request)
    deleted = await runtime.delete_export_sink(principal.tenant_id, sink_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="SIEM export sink not found")
    await runtime.append_audit(
        principal.tenant_id,
        {
            "action": "atr.export_sink.delete",
            "status": "completed",
            "subject": principal.subject,
            "sink_id": sink_id,
        },
    )
    return {"sink_id": sink_id, "deleted": True}
