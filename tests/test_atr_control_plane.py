from types import SimpleNamespace

import pytest

from app.core.atr_policy import apply_atr_exemptions
from app.core.threat_detection import (
    ThreatDetectionUnavailableError,
    ThreatDetector,
)


class MatchingEngine:
    rules = [object()]

    def evaluate(self, event):
        if "hostile" not in event.content:
            return []
        return [
            SimpleNamespace(
                rule_id="ATR-TEST-1",
                title="Test rule",
                severity="critical",
                confidence="high",
            )
        ]


class BrokenEngine:
    rules = [object()]

    def evaluate(self, event):
        raise RuntimeError("scanner offline")


def policy(mode: str, action: str) -> dict[str, object]:
    return {
        "version": 7,
        "mode": mode,
        "minimum_severity": "medium",
        "block_severity": "high",
        "action_map": {
            "informational": "detect",
            "low": "detect",
            "medium": "detect",
            "high": "block",
            "critical": action,
        },
        "enabled_rule_ids": [],
        "excluded_rule_ids": [],
    }


def test_blocking_policy_supports_quarantine_and_privacy_safe_fingerprint() -> None:
    detector = ThreatDetector(engine=MatchingEngine(), fingerprint_secret="test-secret")
    scan = detector.scan(
        "hostile payload",
        event_type="tool_response",
        location="request",
        policy=policy("blocking", "quarantine"),
    )

    assert not scan.blocked and scan.quarantined
    assert scan.to_event()["status"] == "quarantined"
    assert scan.findings[0]["action"] == "quarantine"
    assert scan.findings[0]["policy_version"] == 7
    assert len(scan.findings[0]["content_fingerprint"]) == 64
    assert "hostile payload" not in str(scan.to_event())


def test_detection_only_policy_never_enforces_configured_action() -> None:
    scan = ThreatDetector(engine=MatchingEngine()).scan(
        "hostile payload",
        event_type="llm_input",
        location="request",
        policy=policy("detection_only", "quarantine"),
    )

    assert not scan.blocked
    assert scan.findings[0]["action"] == "detect"


@pytest.mark.asyncio
async def test_scanner_failure_is_closed_in_blocking_and_degraded_in_detection() -> None:
    detector = ThreatDetector(engine=BrokenEngine(), scan_retries=0)
    with pytest.raises(ThreatDetectionUnavailableError):
        await detector.ascan(
            "payload",
            event_type="llm_input",
            location="request",
            policy=policy("blocking", "block"),
        )

    degraded = await detector.ascan(
        "payload",
        event_type="llm_input",
        location="request",
        policy=policy("detection_only", "detect"),
    )
    assert degraded.degraded
    assert degraded.to_event()["status"] == "degraded"


class OneTimeExemption:
    def __init__(self) -> None:
        self.remaining = 1

    async def consume_atr_exemption(self, tenant_id: str, **kwargs) -> bool:
        del tenant_id, kwargs
        if not self.remaining:
            return False
        self.remaining -= 1
        return True


@pytest.mark.asyncio
async def test_exemption_is_consumed_once() -> None:
    detector = ThreatDetector(engine=MatchingEngine())
    original = detector.scan(
        "hostile payload",
        event_type="llm_input",
        location="request",
        policy=policy("blocking", "block"),
    )
    runtime = OneTimeExemption()

    exempted = await apply_atr_exemptions(runtime, "tenant", original)
    second_attempt = await apply_atr_exemptions(runtime, "tenant", original)

    assert not exempted.blocked
    assert exempted.findings[0]["enforcement_action"] == "exempted"
    assert second_attempt.blocked
