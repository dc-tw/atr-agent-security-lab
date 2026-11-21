from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.atr_routes import router
from app.core.atr_policy import default_boundary_action_map
from app.core.config import Settings


class PromotionRuntime:
    def __init__(self, mode: str = "detection_only") -> None:
        self.policy = {
            "policy_id": "policy-1",
            "tenant_id": "default",
            "version": 3,
            "mode": mode,
            "minimum_severity": "medium",
            "block_severity": "high",
            "action_map": default_boundary_action_map()["request_input"],
            "boundary_action_map": default_boundary_action_map(),
            "enabled_rule_ids": [],
            "excluded_rule_ids": [],
        }
        self.audits: list[dict[str, object]] = []

    async def get_active_atr_policy(self, tenant_id: str):  # noqa: ANN201
        return self.policy

    async def create_atr_policy(
        self, tenant_id: str, policy: dict[str, object], *, created_by: str
    ) -> dict[str, object]:
        self.policy = {**policy, "version": 4, "tenant_id": tenant_id, "created_by": created_by}
        return self.policy

    async def append_audit(self, tenant_id: str, payload: dict[str, object]) -> None:
        self.audits.append({"tenant_id": tenant_id, **payload})


def _client(mode: str = "detection_only") -> tuple[TestClient, PromotionRuntime]:
    app = FastAPI()
    app.include_router(router)
    runtime = PromotionRuntime(mode)
    app.state.redis = runtime
    app.state.settings = Settings(
        app_env="development",
        atr_calibration_min_reviews=2,
        atr_promotion_min_reviewers=2,
        atr_promotion_min_kappa=0.8,
    )
    app.state.atr_bundle_manifest = {
        "checksum": "a" * 64,
        "validation_report": {"blocking_eligible": True},
    }
    return TestClient(app), runtime


def _payload(target_mode: str = "shadow") -> dict[str, object]:
    return {
        "source_version": 3,
        "target_mode": target_mode,
        "bundle_checksum": "a" * 64,
        "reviewer_count": 2,
        "cohens_kappa": 1.0,
        "rule_metrics": {
            "ATR-GW-1001": {
                "reviewed_samples": 2,
                "false_positive_rate": 0,
                "false_negative_rate": 0,
            }
        },
    }


def test_promotion_requires_ordered_stage_and_evidence() -> None:
    client, runtime = _client()
    rejected = _payload()
    rejected["reviewer_count"] = 1
    response = client.post("/v1/security/atr/policies/promote", json=rejected)
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "atr_promotion_evidence_rejected"

    promoted = client.post("/v1/security/atr/policies/promote", json=_payload())
    assert promoted.status_code == 200
    assert promoted.json()["mode"] == "shadow"
    assert runtime.audits[-1]["action"] == "atr.policy.promote"


def test_blocking_promotion_requires_shadow_source() -> None:
    client, _ = _client("detection_only")
    response = client.post("/v1/security/atr/policies/promote", json=_payload("blocking"))
    assert response.status_code == 409
    assert response.json()["detail"]["required_target"] == "shadow"
