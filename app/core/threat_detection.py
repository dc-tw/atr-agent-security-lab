from __future__ import annotations

import asyncio
import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from pyatr import AgentEvent, ATREngine

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ATR_BOUNDARIES = (
    "request_input",
    "planner_output",
    "tool_call",
    "tool_response",
    "model_output",
)
BOUNDARY_ALIASES = {
    "llm_input": "request_input",
    "llm_output": "model_output",
}
ALLOWED_BOUNDARY_ACTIONS = {
    "request_input": frozenset({"detect", "block"}),
    "planner_output": frozenset({"detect", "block"}),
    "tool_call": frozenset({"detect", "block", "require_approval"}),
    "tool_response": frozenset({"detect", "block", "quarantine"}),
    "model_output": frozenset({"detect", "block"}),
}


def canonical_boundary(event_type: str) -> str:
    return BOUNDARY_ALIASES.get(event_type, event_type)


@dataclass(frozen=True)
class ThreatScan:
    event_type: str
    location: str
    findings: tuple[dict[str, Any], ...]
    blocked: bool
    truncated: bool = False
    approval_required: bool = False
    quarantined: bool = False
    degraded: bool = False
    error: str = ""
    duration_ms: float = 0.0

    def to_event(self, *, released_before_scan: bool = False) -> dict[str, Any]:
        actions = sorted({str(item.get("action", "detect")) for item in self.findings})
        policy_versions = {
            int(item.get("policy_version", 0))
            for item in self.findings
            if item.get("policy_version")
        }
        bundle_checksums = {
            str(item["bundle_checksum"]) for item in self.findings if item.get("bundle_checksum")
        }
        return {
            "type": "threat_detection",
            "status": (
                "quarantined"
                if self.quarantined
                else "approval_required"
                if self.approval_required
                else "blocked"
                if self.blocked
                else "degraded"
                if self.degraded
                else "detected"
            ),
            "event_type": self.event_type,
            "boundary": canonical_boundary(self.event_type),
            "location": self.location,
            "finding_count": len(self.findings),
            "findings": list(self.findings),
            "finding_ids": [str(item["finding_id"]) for item in self.findings],
            "action": actions[0] if len(actions) == 1 else "mixed" if actions else "detect",
            "policy_version": next(iter(policy_versions)) if len(policy_versions) == 1 else None,
            "bundle_checksum": (
                next(iter(bundle_checksums)) if len(bundle_checksums) == 1 else None
            ),
            "truncated": self.truncated,
            "approval_required": self.approval_required,
            "quarantined": self.quarantined,
            "degraded": self.degraded,
            "released_before_scan": released_before_scan,
            **({"error": self.error} if self.error else {}),
            "duration_ms": round(self.duration_ms, 3),
        }


class ThreatBlockedError(RuntimeError):
    def __init__(self, scan: ThreatScan) -> None:
        self.scan = scan
        rule_ids = ", ".join(item["rule_id"] for item in scan.findings)
        super().__init__(f"ATR blocked {scan.location}: {rule_ids}")


class ThreatDetectionUnavailableError(RuntimeError):
    """Raised when blocking mode cannot prove that content is safe."""


class ThreatDetector:
    """Bounded, privacy-safe adapter around the pyatr Layer-1 rule engine."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        blocking: bool = False,
        min_severity: str = "medium",
        block_severity: str = "high",
        max_content_chars: int = 100_000,
        rules_dir: str = "",
        blocking_rule_ids: list[str] | None = None,
        blocking_excluded_rule_ids: list[str] | None = None,
        engine: ATREngine | None = None,
        scan_retries: int = 2,
        fingerprint_secret: str = "development-only-change-me",
    ) -> None:
        self.enabled = enabled
        self.blocking = blocking
        self.min_severity = min_severity
        self.block_severity = block_severity
        self.max_content_chars = max_content_chars
        self.blocking_rule_ids = frozenset(blocking_rule_ids or [])
        self.blocking_excluded_rule_ids = frozenset(blocking_excluded_rule_ids or [])
        self.scan_retries = scan_retries
        self._fingerprint_secret = fingerprint_secret.encode()
        self.bundle_checksum: str | None = None
        self.engine = engine or ATREngine()
        if not enabled:
            self.rule_count = 0
            return
        if engine is not None:
            self.rule_count = len(engine.rules)
        elif rules_dir:
            self.rule_count = self.engine.load_rules_from_directory(rules_dir)
        else:
            self.rule_count = self.engine.load_default_rules()
        if self.rule_count == 0:
            raise RuntimeError("ATR is enabled but no threat rules were loaded")

    @classmethod
    def from_settings(cls, settings: Any) -> ThreatDetector:
        return cls(
            enabled=settings.atr_enabled,
            blocking=settings.atr_blocking,
            min_severity=settings.atr_min_severity,
            block_severity=settings.atr_block_severity,
            max_content_chars=settings.atr_max_content_chars,
            rules_dir=settings.atr_rules_dir,
            blocking_rule_ids=settings.atr_blocking_rule_ids,
            blocking_excluded_rule_ids=settings.atr_blocking_excluded_rule_ids,
            scan_retries=settings.atr_scan_retries,
            fingerprint_secret=settings.atr_fingerprint_secret,
        )

    def _bounded(self, value: str) -> tuple[str, bool]:
        if len(value) <= self.max_content_chars:
            return value, False
        half = max(1, (self.max_content_chars - 28) // 2)
        return value[:half] + "\n[... ATR scan truncated ...]\n" + value[-half:], True

    def scan(
        self,
        content: str,
        *,
        event_type: str,
        location: str,
        fields: dict[str, object] | None = None,
        metadata: dict[str, object] | None = None,
        policy: dict[str, Any] | None = None,
    ) -> ThreatScan:
        started = time.perf_counter()
        if not self.enabled:
            return ThreatScan(event_type, location, (), False)
        bounded_content, truncated = self._bounded(str(content))
        bounded_fields: dict[str, str] = {}
        for key, value in (fields or {}).items():
            bounded_value, was_truncated = self._bounded(str(value))
            bounded_fields[str(key)] = bounded_value
            truncated = truncated or was_truncated
        matches = self.engine.evaluate(
            AgentEvent(
                content=bounded_content,
                event_type=event_type,
                fields=bounded_fields,
                metadata={str(key): str(value) for key, value in (metadata or {}).items()},
            )
        )
        mode = str((policy or {}).get("mode", "blocking" if self.blocking else "detection_only"))
        min_severity = str((policy or {}).get("minimum_severity", self.min_severity))
        block_severity = str((policy or {}).get("block_severity", self.block_severity))
        enabled_rule_ids = frozenset((policy or {}).get("enabled_rule_ids", self.blocking_rule_ids))
        excluded_rule_ids = frozenset(
            (policy or {}).get("excluded_rule_ids", self.blocking_excluded_rule_ids)
        )
        boundary = canonical_boundary(event_type)
        boundary_maps = (policy or {}).get("boundary_action_map", {})
        boundary_map = (
            dict(boundary_maps.get(boundary, {})) if isinstance(boundary_maps, dict) else {}
        )
        action_map = boundary_map or dict((policy or {}).get("action_map", {}))
        content_fingerprint = hmac.new(
            self._fingerprint_secret,
            str(content).encode(),
            hashlib.sha256,
        ).hexdigest()
        findings_list: list[dict[str, Any]] = []
        for match in matches:
            if SEVERITY_RANK.get(match.severity, 0) < SEVERITY_RANK.get(min_severity, 2):
                continue
            block_candidate = (
                SEVERITY_RANK.get(match.severity, 0) >= SEVERITY_RANK.get(block_severity, 3)
                and (not enabled_rule_ids or match.rule_id in enabled_rule_ids)
                and match.rule_id not in excluded_rule_ids
            )
            configured_action = str(
                action_map.get(match.severity, "block" if block_candidate else "detect")
            )
            action = (
                configured_action
                if mode == "blocking"
                and match.rule_id not in excluded_rule_ids
                and (not enabled_rule_ids or match.rule_id in enabled_rule_ids)
                else "detect"
            )
            if action not in ALLOWED_BOUNDARY_ACTIONS.get(boundary, frozenset({"detect"})):
                action = "block"
            enforcement_status = {
                "detect": "detected",
                "block": "blocked",
                "quarantine": "quarantined",
                "require_approval": "approval_required",
            }.get(action, "detected")
            findings_list.append(
                {
                    "finding_id": str(uuid4()),
                    "rule_id": match.rule_id,
                    "title": match.title,
                    "severity": match.severity,
                    "confidence": match.confidence,
                    "block_candidate": block_candidate,
                    "action": action,
                    "enforcement_action": enforcement_status,
                    "content_fingerprint": content_fingerprint,
                    "content_length": len(str(content)),
                    "policy_version": int((policy or {}).get("version", 0)),
                    "bundle_checksum": self.bundle_checksum,
                    "boundary": boundary,
                }
            )
        findings = tuple(findings_list)
        blocked = any(item["action"] == "block" for item in findings)
        approval_required = any(item["action"] == "require_approval" for item in findings)
        quarantined = any(item["action"] == "quarantine" for item in findings)
        return ThreatScan(
            event_type,
            location,
            findings,
            blocked,
            truncated,
            approval_required,
            quarantined,
            duration_ms=(time.perf_counter() - started) * 1_000,
        )

    async def ascan(
        self,
        content: str,
        *,
        event_type: str,
        location: str,
        fields: dict[str, object] | None = None,
        metadata: dict[str, object] | None = None,
        policy: dict[str, Any] | None = None,
    ) -> ThreatScan:
        """Evaluate CPU-bound regex rules without blocking the async event loop."""
        for attempt in range(self.scan_retries + 1):
            try:
                return await asyncio.to_thread(
                    self.scan,
                    content,
                    event_type=event_type,
                    location=location,
                    fields=fields,
                    metadata=metadata,
                    policy=policy,
                )
            except Exception as exc:
                if attempt < self.scan_retries:
                    await asyncio.sleep(0.05 * (2**attempt))
                    continue
                blocking = str((policy or {}).get("mode", "")) == "blocking" or (
                    policy is None and self.blocking
                )
                if blocking:
                    raise ThreatDetectionUnavailableError(
                        f"ATR unavailable at {location}: {type(exc).__name__}"
                    ) from exc
                return ThreatScan(
                    event_type,
                    location,
                    (),
                    False,
                    degraded=True,
                    error=f"{type(exc).__name__}: {exc}",
                )
