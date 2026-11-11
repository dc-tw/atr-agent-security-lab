from __future__ import annotations

from typing import Any

from app.core.threat_detection import ATR_BOUNDARIES, ThreatScan


def default_boundary_action_map() -> dict[str, dict[str, str]]:
    base = {
        "informational": "detect",
        "low": "detect",
        "medium": "detect",
        "high": "block",
        "critical": "block",
    }
    return {boundary: dict(base) for boundary in ATR_BOUNDARIES}


def default_atr_policy(settings: Any, tenant_id: str) -> dict[str, Any]:
    return {
        "policy_id": None,
        "tenant_id": tenant_id,
        "version": 0,
        "mode": "blocking" if settings.atr_blocking else "detection_only",
        "minimum_severity": settings.atr_min_severity,
        "block_severity": settings.atr_block_severity,
        "action_map": {
            "informational": "detect",
            "low": "detect",
            "medium": "detect",
            "high": "block",
            "critical": "block",
        },
        "boundary_action_map": default_boundary_action_map(),
        "enabled_rule_ids": list(settings.atr_blocking_rule_ids),
        "excluded_rule_ids": list(settings.atr_blocking_excluded_rule_ids),
        "active": True,
        "created_by": "configuration-default",
        "created_at": None,
    }


async def active_atr_policy(runtime: Any, settings: Any, tenant_id: str) -> dict[str, Any]:
    if runtime is not None and hasattr(runtime, "get_active_atr_policy"):
        policy = await runtime.get_active_atr_policy(tenant_id)
        if policy is not None:
            return policy
    return default_atr_policy(settings, tenant_id)


async def apply_atr_exemptions(runtime: Any, tenant_id: str, scan: ThreatScan) -> ThreatScan:
    if runtime is None or not hasattr(runtime, "consume_atr_exemption"):
        return scan
    findings: list[dict[str, Any]] = []
    changed = False
    for original in scan.findings:
        finding = dict(original)
        if finding.get("action") in {"block", "quarantine", "require_approval"}:
            exempted = await runtime.consume_atr_exemption(
                tenant_id,
                rule_id=str(finding["rule_id"]),
                boundary=scan.event_type,
                content_fingerprint=str(finding.get("content_fingerprint", "")),
                bundle_checksum=finding.get("bundle_checksum"),
                policy_version=int(finding.get("policy_version", 0)),
            )
            if exempted:
                finding.update(
                    {
                        "action": "detect",
                        "enforcement_action": "exempted",
                        "exemption_applied": True,
                    }
                )
                changed = True
        findings.append(finding)
    if not changed:
        return scan
    blocked = any(finding.get("action") == "block" for finding in findings)
    return ThreatScan(
        event_type=scan.event_type,
        location=scan.location,
        findings=tuple(findings),
        blocked=blocked,
        truncated=scan.truncated,
        approval_required=any(finding.get("action") == "require_approval" for finding in findings),
        quarantined=any(finding.get("action") == "quarantine" for finding in findings),
        degraded=scan.degraded,
        error=scan.error,
        duration_ms=scan.duration_ms,
    )
