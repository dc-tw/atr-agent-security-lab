from __future__ import annotations

from collections.abc import AsyncIterator
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command
from pydantic import ValidationError

from app.api.atr_routes import ATRPolicyWrite
from app.core.atr_policy import default_boundary_action_map
from app.core.atr_rules import rule_bundle_manifest
from app.core.threat_detection import ThreatBlockedError, ThreatDetector
from app.graph.workflow import build_agent_graph, initial_state
from app.lab_services.deployment_simulator import app as deployment_app
from app.tools.registry import ToolSpec


class MarkerEngine:
    rules = [object()]

    def __init__(self, boundary: str | None = None) -> None:
        self.boundary = boundary

    def evaluate(self, event):
        if (self.boundary and event.event_type != self.boundary) or (
            "hostile" not in event.content.lower()
        ):
            return []
        return [
            SimpleNamespace(
                rule_id="ATR-LAB-1",
                title="Lab marker",
                severity="critical",
                confidence="high",
            )
        ]


def boundary_policy(boundary: str, action: str) -> dict[str, object]:
    mapping = default_boundary_action_map()
    mapping[boundary]["critical"] = action
    return {
        "version": 11,
        "mode": "blocking",
        "minimum_severity": "medium",
        "block_severity": "high",
        "action_map": mapping[boundary],
        "boundary_action_map": mapping,
        "enabled_rule_ids": [],
        "excluded_rule_ids": [],
    }


class SequenceModel:
    def __init__(self, complete: list[str], stream: str) -> None:
        self._complete = iter(complete)
        self._stream = stream
        self.stream_prompts: list[str] = []

    async def complete(self, system: str, prompt: str) -> str:
        return next(self._complete)

    async def stream(self, system: str, prompt: str) -> AsyncIterator[str]:
        self.stream_prompts.append(prompt)
        yield self._stream


class RecordingLabTools:
    def __init__(self, result: dict[str, object] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.result = result or {"deployment_id": 1, "status": "deployed"}

    def specs(self) -> list[ToolSpec]:
        return [
            ToolSpec("read_untrusted_page", "read fixture"),
            ToolSpec("deploy_release", "deploy", requires_approval=True),
        ]

    async def invoke(self, name: str, arguments: dict[str, object]) -> dict[str, object]:
        self.calls.append((name, arguments))
        return self.result


def test_policy_rejects_actions_that_are_invalid_for_a_boundary() -> None:
    mapping = default_boundary_action_map()
    mapping["model_output"]["critical"] = "require_approval"
    with pytest.raises(ValidationError):
        ATRPolicyWrite(mode="blocking", boundary_action_map=mapping)


def test_invalid_rule_condition_is_disabled_and_reported() -> None:
    condition = lambda value: SimpleNamespace(  # noqa: E731 - compact rule fixture
        field="content", operator="regex", value=value
    )
    invalid = SimpleNamespace(
        id="ATR-2026-00290",
        title="invalid regex",
        severity="high",
        status="active",
        tags={},
        conditions=[condition(r"(secret)\2")],
    )
    valid = SimpleNamespace(
        id="ATR-LAB-VALID",
        title="valid regex",
        severity="high",
        status="active",
        tags={},
        conditions=[condition(r"secret")],
    )
    engine = SimpleNamespace(
        rules=[invalid, valid],
        _rules=[invalid, valid],
        _compiled={invalid.id: object(), valid.id: object()},
        _failed_regexes=set(),
    )
    detector = SimpleNamespace(engine=engine, rule_count=2, bundle_checksum=None)

    manifest = rule_bundle_manifest(detector, "")

    assert manifest["validation_report"]["degraded"] is True
    assert manifest["validation_report"]["blocking_eligible"] is False
    assert manifest["validation_report"]["invalid_rule_ids"] == ["ATR-2026-00290"]
    assert [rule["rule_id"] for rule in manifest["rules"]] == ["ATR-LAB-VALID"]
    assert detector.rule_count == 1


@pytest.mark.asyncio
async def test_planner_output_is_scanned_before_parsing_or_tool_execution() -> None:
    model = SequenceModel(["hostile planner output"], "unused")
    tools = RecordingLabTools()
    graph = build_agent_graph(
        model,
        object(),
        tool_executor=tools,
        threat_detector=ThreatDetector(engine=MarkerEngine("planner_output")),
        atr_policy=boundary_policy("planner_output", "block"),
    )

    with pytest.raises(ThreatBlockedError):
        _ = [
            event
            async for event in graph.astream(
                initial_state("planner-block", "Use the website for this task", None, 0),
                stream_mode="custom",
            )
        ]
    assert tools.calls == []


@pytest.mark.asyncio
async def test_quarantine_replaces_tool_response_before_model_context() -> None:
    model = SequenceModel(
        [
            '{"tool":"read_untrusted_page","arguments":{"fixture_id":"indirect-injection"}}',
            '{"tool":null,"arguments":{}}',
        ],
        "The untrusted tool content was quarantined before it could be used.",
    )
    tools = RecordingLabTools(
        {
            "fixture_id": "indirect-injection",
            "text": "hostile tool payload",
            "content_sha256": "not-persisted",
        }
    )
    graph = build_agent_graph(
        model,
        object(),
        tool_executor=tools,
        threat_detector=ThreatDetector(engine=MarkerEngine("tool_response")),
        atr_policy=boundary_policy("tool_response", "quarantine"),
    )
    events = [
        event
        async for event in graph.astream(
            initial_state("quarantine", "Use the website fixture", None, 0),
            stream_mode="custom",
        )
    ]

    threat = next(event for event in events if event.get("type") == "threat_detection")
    assert threat["status"] == "quarantined"
    assert "hostile tool payload" not in str(events)
    assert model.stream_prompts and "hostile tool payload" not in model.stream_prompts[0]
    assert "ATR quarantined" in model.stream_prompts[0]


@pytest.mark.asyncio
async def test_atr_and_tool_approvals_are_distinct_and_side_effect_is_once() -> None:
    model = SequenceModel(
        [
            '{"tool":"deploy_release","arguments":{"environment":"staging",'
            '"version":"1.2.3","change":"hostile but reviewed change"}}',
            '{"tool":null,"arguments":{}}',
        ],
        "The approved lab deployment completed exactly once.",
    )
    tools = RecordingLabTools()
    graph = build_agent_graph(
        model,
        object(),
        tool_executor=tools,
        checkpointer=MemorySaver(),
        threat_detector=ThreatDetector(engine=MarkerEngine("tool_call")),
        atr_policy=boundary_policy("tool_call", "require_approval"),
    )
    config = {"configurable": {"thread_id": "two-approvals"}}
    first = [
        event
        async for event in graph.astream(
            initial_state(
                "two-approvals",
                "Use the deployment tool",
                None,
                0,
                interactive_approval=True,
            ),
            config=config,
            stream_mode="custom",
        )
    ]
    atr = next(event for event in first if event.get("type") == "approval_required")
    assert atr["kind"] == "atr"
    assert tools.calls == []

    second = [
        event
        async for event in graph.astream(
            Command(
                resume={
                    "approved": True,
                    "kind": "atr",
                    "approval_id": atr["approval_id"],
                }
            ),
            config=config,
            stream_mode="custom",
        )
    ]
    tool = next(
        event
        for event in second
        if event.get("type") == "approval_required" and event.get("kind") == "tool"
    )
    assert tool["kind"] == "tool"
    assert tools.calls == []

    _ = [
        event
        async for event in graph.astream(
            Command(
                resume={
                    "approved": True,
                    "kind": "tool",
                    "approval_id": tool["approval_id"],
                }
            ),
            config=config,
            stream_mode="custom",
        )
    ]
    assert len(tools.calls) == 1
    assert len(str(tools.calls[0][1]["_idempotency_key"])) == 64


def test_deployment_simulator_is_idempotent(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ATR_LAB_DEPLOYMENT_DB", str(tmp_path / "deployments.sqlite3"))
    headers = {
        "x-atr-lab-token": "development-only-change-me",
        "idempotency-key": "a" * 32,
    }
    payload = {"environment": "staging", "version": "1.2.3", "change": "safe"}
    with TestClient(deployment_app) as client:
        first = client.post("/deployments", headers=headers, json=payload)
        second = client.post("/deployments", headers=headers, json=payload)
        listing = client.get(
            "/deployments", headers={"x-atr-lab-token": "development-only-change-me"}
        )
    assert first.status_code == second.status_code == 200
    assert first.json()["deployment_id"] == second.json()["deployment_id"]
    assert listing.json()["count"] == 1
