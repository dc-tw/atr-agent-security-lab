from __future__ import annotations

# ruff: noqa: E501 -- SQL statements are kept whole so evidence schema audits stay readable.
import asyncio
import hashlib
import json
import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app.lab_services.compound_policy import (
    ARTIFACTS,
    BUNDLE_CHECKSUM,
    IDENTITIES,
    POLICY_VERSION,
    Decision,
    evaluate_atr,
    evaluate_deployment,
    evaluate_iam,
    evaluate_signing,
    evaluate_supply_chain,
    fingerprint,
)

app = FastAPI(title="Compound Agent Attack Chain Scenario Runner")
PROCESS_INSTANCE = uuid4().hex
PROFILES = {
    "protected",
    "baseline",
    "bypass_iam",
    "bypass_supply_chain",
    "bypass_deployment",
    "bypass_signing",
}
SCENARIOS = {
    "benign",
    "indirect_injection",
    "stolen_session_wrong_device",
    "compromised_device_cross_scope",
    "stolen_deployment_token",
    "tampered_artifact",
    "unsigned_artifact",
    "revoked_signer",
    "unknown_image",
    "unknown_builder",
    "self_approval",
    "no_customer_intent",
    "unknown_destination",
    "excessive_amount",
    "eip7702_delegation",
    "nonce_burst",
    "baseline_theft",
    "atr_timeout",
    "credential_broker_timeout",
    "iam_timeout",
    "artifact_registry_timeout",
    "deployment_timeout",
    "signing_timeout",
}
APPROVER_SUBJECTS = {
    "security_reviewer": "security-reviewer",
    "operations_reviewer": "operations-reviewer",
    "wallet_approver": "wallet-approver",
}


class RunCreate(BaseModel):
    scenario_id: str
    control_profile: str = "protected"
    model: str = "deterministic-mock"
    pause_at: str = Field(
        default="", pattern=r"^(|before_deployment|before_signing|after_signing)$"
    )


class ApprovalDecision(BaseModel):
    decision: str = Field(pattern=r"^(approve|reject)$")
    content_fingerprint: str
    policy_version: str


class RunMutation(BaseModel):
    kind: str = Field(pattern=r"^(policy|bundle|artifact|credential|payload)$")


class CorpusReview(BaseModel):
    verdict: str = Field(pattern=r"^(true_positive|false_positive|acceptable_risk)$")
    reason: str = Field(min_length=1, max_length=500)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _db() -> sqlite3.Connection:
    path = os.getenv("ATR_LAB_COMPOUND_DB", "/data/compound.sqlite3")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.executescript("""
    CREATE TABLE IF NOT EXISTS compound_runs(
      run_id TEXT PRIMARY KEY, scenario_id TEXT NOT NULL, control_profile TEXT NOT NULL,
      model TEXT NOT NULL, requester TEXT NOT NULL, status TEXT NOT NULL, current_stage TEXT NOT NULL,
      stopped_layer TEXT, policy_version TEXT NOT NULL, bundle_checksum TEXT NOT NULL,
      content_fingerprint TEXT NOT NULL, artifact_id TEXT NOT NULL, image_digest TEXT NOT NULL,
      deployment_count INTEGER NOT NULL DEFAULT 0, signing_count INTEGER NOT NULL DEFAULT 0,
      mutation_version INTEGER NOT NULL DEFAULT 0, pause_at TEXT NOT NULL DEFAULT '',
      pause_owner TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS compound_events(
      event_id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, sequence INTEGER NOT NULL,
      stage TEXT NOT NULL, layer TEXT NOT NULL, decision TEXT NOT NULL, reason_code TEXT NOT NULL,
      receipt_id TEXT NOT NULL, prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL, created_at TEXT NOT NULL,
      UNIQUE(run_id, sequence));
    CREATE TABLE IF NOT EXISTS compound_approvals(
      approval_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, required_role TEXT NOT NULL,
      requester TEXT NOT NULL, decision_maker TEXT, status TEXT NOT NULL,
      content_fingerprint TEXT NOT NULL, policy_version TEXT NOT NULL, expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS corpus_review_cases(
      case_id TEXT PRIMARY KEY, boundary TEXT NOT NULL, rule_id TEXT NOT NULL,
      sample_fingerprint TEXT NOT NULL, expected_verdict TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS corpus_reviews(
      case_id TEXT NOT NULL, reviewer TEXT NOT NULL, verdict TEXT NOT NULL, reason TEXT NOT NULL,
      created_at TEXT NOT NULL, PRIMARY KEY(case_id, reviewer));
    """)
    columns = {row[1] for row in connection.execute("PRAGMA table_info(compound_runs)")}
    for name, definition in (
        ("mutation_version", "INTEGER NOT NULL DEFAULT 0"),
        ("pause_at", "TEXT NOT NULL DEFAULT ''"),
        ("pause_owner", "TEXT NOT NULL DEFAULT ''"),
    ):
        if name not in columns:
            connection.execute(f"ALTER TABLE compound_runs ADD COLUMN {name} {definition}")
    review_cases = (
        ("request-canary", "request_input", "COMPOUND-CANARY", "true_positive"),
        ("tool-credential", "tool_call", "COMPOUND-CREDENTIAL-EXFIL", "true_positive"),
        ("response-remote", "tool_response", "COMPOUND-REMOTE-CONTROL", "true_positive"),
        ("planner-near-miss", "planner_output", "COMPOUND-POLICY-BYPASS", "false_positive"),
        ("output-benign", "model_output", "COMPOUND-MALICIOUS-DEPLOY", "false_positive"),
    )
    connection.executemany(
        "INSERT OR IGNORE INTO corpus_review_cases(case_id,boundary,rule_id,sample_fingerprint,expected_verdict) VALUES(?,?,?,?,?)",
        [
            (*case[:3], fingerprint({"case_id": case[0], "boundary": case[1]}), case[3])
            for case in review_cases
        ],
    )
    connection.commit()
    return connection


def _auth(token: str) -> None:
    if token != os.getenv("ATR_LAB_INTERNAL_TOKEN", "development-only-change-me"):
        raise HTTPException(401, "invalid lab token")


def _event(connection: sqlite3.Connection, run_id: str, stage: str, decision: Decision) -> None:
    previous = connection.execute(
        "SELECT sequence,event_hash FROM compound_events WHERE run_id=? ORDER BY sequence DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    sequence = int(previous["sequence"]) + 1 if previous else 1
    prev_hash = str(previous["event_hash"]) if previous else "GENESIS"
    receipt_id = str(uuid4())
    body = {
        "run_id": run_id,
        "sequence": sequence,
        "stage": stage,
        **decision.as_dict(),
        "receipt_id": receipt_id,
        "prev_hash": prev_hash,
    }
    event_hash = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    connection.execute(
        "INSERT INTO compound_events(run_id,sequence,stage,layer,decision,reason_code,receipt_id,prev_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (
            run_id,
            sequence,
            stage,
            decision.layer,
            decision.decision,
            decision.reason_code,
            receipt_id,
            prev_hash,
            event_hash,
            _now(),
        ),
    )


def _deny(connection: sqlite3.Connection, run_id: str, stage: str, decision: Decision) -> None:
    _event(connection, run_id, stage, decision)
    connection.execute(
        "UPDATE compound_runs SET status='blocked',current_stage=?,stopped_layer=?,updated_at=? WHERE run_id=?",
        (stage, decision.layer, _now(), run_id),
    )


def _approval(connection: sqlite3.Connection, run: sqlite3.Row, role: str) -> None:
    approval_id = str(uuid4())
    now = datetime.now(UTC)
    connection.execute(
        "INSERT INTO compound_approvals(approval_id,run_id,required_role,requester,status,content_fingerprint,policy_version,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (
            approval_id,
            run["run_id"],
            role,
            run["requester"],
            "pending",
            run["content_fingerprint"],
            POLICY_VERSION,
            (now + timedelta(hours=1)).isoformat(),
            now.isoformat(),
            now.isoformat(),
        ),
    )
    _event(
        connection,
        run["run_id"],
        "approval",
        Decision("approval", "approval", f"{role.upper()}_REQUIRED"),
    )


def _scenario_values(scenario: str) -> dict[str, object]:
    values: dict[str, object] = {
        "subject": "engineer-a",
        "device": "device-A",
        "target": "wallet",
        "artifact_id": "wallet-v1-signed",
        "image_digest": "sha256:wallet-v1",
        "synthetic_threat": False,
        "intent_id": "intent-001",
        "destination": "treasury-cold",
        "amount_atomic": "1000",
        "operation": "transfer",
        "nonce_reused": False,
        "credential_marker": "CREDENTIAL-CANARY-DO-NOT-STORE",
    }
    changes = {
        "indirect_injection": {"synthetic_threat": True},
        "stolen_session_wrong_device": {"device": "device-B"},
        "compromised_device_cross_scope": {"target": "application"},
        "stolen_deployment_token": {"token_device": "device-B"},
        "tampered_artifact": {
            "artifact_id": "wallet-v1-tampered",
            "image_digest": "sha256:tampered",
        },
        "unsigned_artifact": {
            "artifact_id": "wallet-v1-unsigned",
            "image_digest": "sha256:unsigned",
        },
        "revoked_signer": {"artifact_id": "wallet-v1-revoked", "image_digest": "sha256:revoked"},
        "unknown_image": {"image_digest": "sha256:not-registered"},
        "unknown_builder": {
            "artifact_id": "wallet-v1-unknown-builder",
            "image_digest": "sha256:unknown-builder",
        },
        "no_customer_intent": {"intent_id": ""},
        "unknown_destination": {"destination": "attacker-destination"},
        "excessive_amount": {"amount_atomic": "1000001"},
        "eip7702_delegation": {"operation": "delegation_authorization"},
        "nonce_burst": {"nonce_reused": True},
        "baseline_theft": {
            "intent_id": "",
            "destination": "attacker-destination",
            "amount_atomic": "1000001",
        },
    }
    values.update(changes.get(scenario, {}))
    return values


def _run_chain(connection: sqlite3.Connection, run_id: str) -> None:
    run = connection.execute("SELECT * FROM compound_runs WHERE run_id=?", (run_id,)).fetchone()
    assert run is not None
    scenario, profile = run["scenario_id"], run["control_profile"]
    values = _scenario_values(scenario)
    if profile == "baseline":
        for layer in ("atr", "iam", "supply_chain", "deployment", "signing"):
            _event(
                connection, run_id, layer, Decision(layer, "allow", "LAB_ADMIN_CONTROLLED_BYPASS")
            )
        connection.execute(
            "UPDATE compound_runs SET status='executing',current_stage='side_effects',updated_at=? WHERE run_id=?",
            (_now(), run_id),
        )
        return
    decisions = [
        (
            "atr",
            evaluate_atr(
                synthetic_threat=bool(values["synthetic_threat"]),
                available=scenario != "atr_timeout",
            ),
        ),
        (
            "iam",
            evaluate_iam(
                subject=str(values["subject"]),
                device=str(values["device"]),
                target=str(values["target"]),
                token_claims={
                    "subject": values["subject"],
                    "device": values.get("token_device", values["device"]),
                    "audience": "deployment",
                    "scope": values["target"],
                    "artifact_digest": values["image_digest"],
                    "valid": True,
                },
                artifact_digest=str(values["image_digest"]),
                available=scenario not in {"iam_timeout", "credential_broker_timeout"},
            ),
        ),
        (
            "supply_chain",
            evaluate_supply_chain(
                artifact_id=str(values["artifact_id"]),
                image_digest=str(values["image_digest"]),
                available=scenario != "artifact_registry_timeout",
            ),
        ),
        (
            "deployment",
            evaluate_deployment(
                artifact_id=str(values["artifact_id"]),
                environment="production",
                available=scenario != "deployment_timeout",
            ),
        ),
    ]
    bypass_layers = {
        "bypass_iam": {"atr", "iam"},
        "bypass_supply_chain": {"atr", "iam", "supply_chain"},
        "bypass_deployment": {"atr", "iam", "supply_chain", "deployment"},
        "bypass_signing": {"atr", "iam", "supply_chain", "deployment", "signing"},
    }.get(profile, set())
    for stage, decision in decisions:
        if stage in bypass_layers:
            decision = Decision(stage, "allow", "LAB_ADMIN_CONTROLLED_BYPASS")
        if decision.decision in {"deny", "degraded"}:
            _deny(connection, run_id, stage, decision)
            return
        _event(connection, run_id, stage, decision)
    if "deployment" not in bypass_layers:
        _approval(connection, run, "security_reviewer")
        _approval(connection, run, "operations_reviewer")
        connection.execute(
            "UPDATE compound_runs SET status='waiting_approval',current_stage='deployment_approval',updated_at=? WHERE run_id=?",
            (_now(), run_id),
        )
        return
    _advance_to_signing(connection, run_id, bypass_layers)


def _advance_to_signing(
    connection: sqlite3.Connection, run_id: str, bypass_layers: set[str] | None = None
) -> None:
    run = connection.execute("SELECT * FROM compound_runs WHERE run_id=?", (run_id,)).fetchone()
    assert run is not None
    values = _scenario_values(run["scenario_id"])
    bypass_layers = bypass_layers or set()
    decision = evaluate_signing(
        operation=str(values["operation"]),
        amount_atomic=str(values["amount_atomic"]),
        destination=str(values["destination"]),
        intent_id=str(values["intent_id"]),
        workload_attested=True,
        nonce_reused=bool(values["nonce_reused"]),
        available=run["scenario_id"] != "signing_timeout",
    )
    if "signing" in bypass_layers:
        decision = Decision("signing", "allow", "LAB_ADMIN_CONTROLLED_BYPASS")
    if decision.decision in {"deny", "degraded"}:
        _deny(connection, run_id, "signing", decision)
        return
    _event(connection, run_id, "signing", decision)
    if decision.decision == "approval":
        _approval(connection, run, "wallet_approver")
        connection.execute(
            "UPDATE compound_runs SET status='waiting_approval',current_stage='signing_approval',updated_at=? WHERE run_id=?",
            (_now(), run_id),
        )
    else:
        connection.execute(
            "UPDATE compound_runs SET status='executing',current_stage='side_effects',updated_at=? WHERE run_id=?",
            (_now(), run_id),
        )


def _pause_at(connection: sqlite3.Connection, run: sqlite3.Row, point: str) -> bool:
    if run["pause_at"] != point or run["pause_owner"]:
        return False
    connection.execute(
        "UPDATE compound_runs SET status='paused_failpoint',current_stage=?,pause_owner=?,updated_at=? WHERE run_id=?",
        (point, PROCESS_INSTANCE, _now(), run["run_id"]),
    )
    _event(
        connection,
        str(run["run_id"]),
        point,
        Decision("runner", "approval", f"FAILPOINT_{point.upper()}_ARMED"),
    )
    connection.commit()
    return True


async def _require_service_health(
    client: httpx.AsyncClient, url: str, headers: dict[str, str]
) -> None:
    last_error: Exception | None = None
    for attempt in range(5):
        try:
            response = await client.get(url + "/healthz", headers=headers)
            response.raise_for_status()
            if response.json().get("status") != "ok":
                raise ValueError("service health evidence is invalid")
            return
        except (httpx.HTTPError, ValueError) as exc:
            last_error = exc
            if attempt < 4:
                await asyncio.sleep(0.25)
    assert last_error is not None
    raise last_error


async def _execute_side_effects(connection: sqlite3.Connection, run_id: str) -> None:
    run = connection.execute("SELECT * FROM compound_runs WHERE run_id=?", (run_id,)).fetchone()
    assert run is not None
    if run["status"] == "completed" or run["status"] == "blocked":
        return
    if run["status"] == "paused_failpoint":
        if run["pause_owner"] == PROCESS_INSTANCE:
            return
        connection.execute(
            "UPDATE compound_runs SET status='executing',pause_at='',pause_owner='',updated_at=? WHERE run_id=?",
            (_now(), run_id),
        )
        _event(
            connection,
            run_id,
            "resume",
            Decision("runner", "allow", "RUNNER_PROCESS_RESTART_RESUME"),
        )
        connection.commit()
        run = connection.execute("SELECT * FROM compound_runs WHERE run_id=?", (run_id,)).fetchone()
        assert run is not None
    if int(run["deployment_count"]) == 0 and _pause_at(connection, run, "before_deployment"):
        return
    values = _scenario_values(run["scenario_id"])
    headers = {"x-atr-lab-token": os.getenv("ATR_LAB_INTERNAL_TOKEN", "development-only-change-me")}
    deployment_url = os.getenv("ATR_LAB_DEPLOYMENT_URL", "http://deployment-simulator:8030")
    signing_url = os.getenv("ATR_LAB_SIGNING_URL", "http://signing-simulator:8050")
    failure_layer = "deployment"
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            if int(run["deployment_count"]) == 0:
                await _require_service_health(client, deployment_url, headers)
                failure_layer = "signing"
                await _require_service_health(client, signing_url, headers)
                failure_layer = "deployment"
                deployment = await client.post(
                    deployment_url + "/compound-deployments",
                    headers=headers,
                    json={
                        "run_id": run_id,
                        "environment": "production",
                        "artifact_id": values["artifact_id"],
                        "image_digest": values["image_digest"],
                        "artifact_fingerprint": fingerprint(
                            ARTIFACTS.get(str(values["artifact_id"]), {})
                        ),
                    },
                )
                deployment.raise_for_status()
                deployment_payload = deployment.json()
                if not isinstance(deployment_payload, dict) or not deployment_payload.get(
                    "deployment_id"
                ):
                    raise ValueError("deployment simulator returned invalid evidence")
                connection.execute(
                    "UPDATE compound_runs SET deployment_count=1,current_stage='deployment_committed',updated_at=? WHERE run_id=?",
                    (_now(), run_id),
                )
                connection.commit()
            run = connection.execute(
                "SELECT * FROM compound_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            assert run is not None
            if int(run["signing_count"]) == 0 and _pause_at(connection, run, "before_signing"):
                return
            if int(run["signing_count"]) == 0:
                failure_layer = "signing"
                signature = await client.post(
                    signing_url + "/signatures",
                    headers=headers,
                    json={
                        "run_id": run_id,
                        "wallet_id": "wallet-lab-1",
                        "operation": values["operation"],
                        "amount_atomic": values["amount_atomic"],
                        "destination_fingerprint": fingerprint(values["destination"]),
                        "payload_fingerprint": run["content_fingerprint"],
                    },
                )
                signature.raise_for_status()
                signature_payload = signature.json()
                if not isinstance(signature_payload, dict) or not signature_payload.get(
                    "signature_id"
                ):
                    raise ValueError("signing simulator returned invalid evidence")
                connection.execute(
                    "UPDATE compound_runs SET signing_count=1,current_stage='signing_committed',updated_at=? WHERE run_id=?",
                    (_now(), run_id),
                )
                connection.commit()
    except (httpx.HTTPError, ValueError):
        _deny(
            connection,
            run_id,
            failure_layer,
            Decision(
                failure_layer,
                "degraded",
                f"{failure_layer.upper()}_SERVICE_UNAVAILABLE_FAIL_CLOSED",
            ),
        )
        connection.commit()
        return
    run = connection.execute("SELECT * FROM compound_runs WHERE run_id=?", (run_id,)).fetchone()
    assert run is not None
    if _pause_at(connection, run, "after_signing"):
        return
    connection.execute(
        "UPDATE compound_runs SET status='completed',current_stage='complete',deployment_count=1,signing_count=1,updated_at=? WHERE run_id=?",
        (_now(), run_id),
    )
    _event(
        connection,
        run_id,
        "complete",
        Decision("runner", "allow", "SYNTHETIC_SIDE_EFFECTS_COMMITTED_ONCE"),
    )


def _serialize_run(connection: sqlite3.Connection, run_id: str) -> dict[str, object]:
    row = connection.execute("SELECT * FROM compound_runs WHERE run_id=?", (run_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "run not found")
    result = dict(row)
    approvals = connection.execute(
        "SELECT approval_id,required_role,status,decision_maker,expires_at,content_fingerprint,policy_version FROM compound_approvals WHERE run_id=? ORDER BY created_at",
        (run_id,),
    ).fetchall()
    result["approvals"] = [dict(item) for item in approvals]
    return result


@app.get("/healthz")
async def health() -> dict[str, str]:
    with closing(_db()) as connection:
        connection.execute("SELECT 1")
        resumable = connection.execute(
            "SELECT run_id FROM compound_runs WHERE status IN ('executing','paused_failpoint')"
        ).fetchall()
        for row in resumable:
            await _execute_side_effects(connection, str(row["run_id"]))
        connection.commit()
    return {"status": "ok"}


@app.post("/compound-runs")
async def create_run(
    payload: RunCreate,
    x_atr_lab_token: str = Header(default=""),
    x_lab_subject: str = Header(default="lab-admin"),
    x_lab_role: str = Header(default="admin"),
) -> dict[str, object]:
    _auth(x_atr_lab_token)
    if payload.scenario_id not in SCENARIOS or payload.control_profile not in PROFILES:
        raise HTTPException(422, "unknown scenario or predefined control profile")
    if payload.control_profile != "protected" and x_lab_role != "admin":
        raise HTTPException(403, "Lab admin required for controlled bypass profiles")
    run_id = str(uuid4())
    values = _scenario_values(payload.scenario_id)
    content_fingerprint = fingerprint(
        {
            "scenario": payload.scenario_id,
            "profile": payload.control_profile,
            "values": values,
            "policy": POLICY_VERSION,
            "bundle": BUNDLE_CHECKSUM,
        }
    )
    now = _now()
    with closing(_db()) as connection:
        connection.execute(
            "INSERT INTO compound_runs(run_id,scenario_id,control_profile,model,requester,status,current_stage,policy_version,bundle_checksum,content_fingerprint,artifact_id,image_digest,pause_at,created_at,updated_at) VALUES(?,?,?,?,?,'running','initial',?,?,?,?,?,?,?,?)",
            (
                run_id,
                payload.scenario_id,
                payload.control_profile,
                payload.model,
                x_lab_subject,
                POLICY_VERSION,
                BUNDLE_CHECKSUM,
                content_fingerprint,
                values["artifact_id"],
                values["image_digest"],
                payload.pause_at,
                now,
                now,
            ),
        )
        _run_chain(connection, run_id)
        connection.commit()
        result = _serialize_run(connection, run_id)
        if result["status"] == "executing":
            await _execute_side_effects(connection, run_id)
            connection.commit()
            result = _serialize_run(connection, run_id)
    return result


@app.get("/compound-runs")
async def list_runs(x_atr_lab_token: str = Header(default="")) -> dict[str, object]:
    _auth(x_atr_lab_token)
    with closing(_db()) as connection:
        rows = connection.execute(
            "SELECT run_id,scenario_id,control_profile,model,status,current_stage,stopped_layer,deployment_count,signing_count,policy_version,bundle_checksum,created_at,updated_at FROM compound_runs ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
    return {"runs": [dict(row) for row in rows]}


@app.get("/compound-runs/{run_id}")
async def get_run(run_id: str, x_atr_lab_token: str = Header(default="")) -> dict[str, object]:
    _auth(x_atr_lab_token)
    with closing(_db()) as connection:
        return _serialize_run(connection, run_id)


@app.get("/compound-runs/{run_id}/events")
async def events(run_id: str, x_atr_lab_token: str = Header(default="")) -> dict[str, object]:
    _auth(x_atr_lab_token)
    with closing(_db()) as connection:
        rows = connection.execute(
            "SELECT sequence,stage,layer,decision,reason_code,receipt_id,prev_hash,event_hash,created_at FROM compound_events WHERE run_id=? ORDER BY sequence",
            (run_id,),
        ).fetchall()
    return {"events": [dict(row) for row in rows]}


@app.post("/compound-runs/{run_id}/approvals/{approval_id}")
async def decide(
    run_id: str,
    approval_id: str,
    payload: ApprovalDecision,
    x_atr_lab_token: str = Header(default=""),
    x_lab_subject: str = Header(default=""),
    x_lab_device_id: str = Header(default=""),
) -> dict[str, object]:
    _auth(x_atr_lab_token)
    with closing(_db()) as connection:
        approval = connection.execute(
            "SELECT * FROM compound_approvals WHERE approval_id=? AND run_id=?",
            (approval_id, run_id),
        ).fetchone()
        run = connection.execute("SELECT * FROM compound_runs WHERE run_id=?", (run_id,)).fetchone()
        if approval is None or run is None:
            raise HTTPException(404, "approval not found")
        if approval["status"] != "pending":
            raise HTTPException(409, "approval already decided")
        if (
            payload.content_fingerprint != approval["content_fingerprint"]
            or payload.policy_version != approval["policy_version"]
            or approval["content_fingerprint"] != run["content_fingerprint"]
            or approval["policy_version"] != run["policy_version"]
        ):
            raise HTTPException(409, "approval invalidated by content or policy change")
        if datetime.fromisoformat(approval["expires_at"]) <= datetime.now(UTC):
            raise HTTPException(409, "approval expired")
        if (
            x_lab_subject == run["requester"]
            or APPROVER_SUBJECTS[approval["required_role"]] != x_lab_subject
        ):
            raise HTTPException(403, "required independent approver role not satisfied")
        identity = IDENTITIES.get(x_lab_subject)
        if identity is None or identity["device"] != x_lab_device_id:
            raise HTTPException(403, "approver device binding failed")
        status = "approved" if payload.decision == "approve" else "rejected"
        connection.execute(
            "UPDATE compound_approvals SET status=?,decision_maker=?,updated_at=? WHERE approval_id=?",
            (status, x_lab_subject, _now(), approval_id),
        )
        _event(
            connection,
            run_id,
            "approval",
            Decision("approval", status, f"{approval['required_role'].upper()}_{status.upper()}"),
        )
        if status == "rejected":
            connection.execute(
                "UPDATE compound_runs SET status='blocked',current_stage='approval',stopped_layer='approval',updated_at=? WHERE run_id=?",
                (_now(), run_id),
            )
        else:
            pending = connection.execute(
                "SELECT COUNT(*) FROM compound_approvals WHERE run_id=? AND status='pending'",
                (run_id,),
            ).fetchone()[0]
            current = connection.execute(
                "SELECT current_stage FROM compound_runs WHERE run_id=?", (run_id,)
            ).fetchone()[0]
            if pending == 0 and current == "deployment_approval":
                _advance_to_signing(connection, run_id)
            elif pending == 0 and current == "signing_approval":
                connection.execute(
                    "UPDATE compound_runs SET status='executing',current_stage='side_effects',updated_at=? WHERE run_id=?",
                    (_now(), run_id),
                )
        connection.commit()
        result = _serialize_run(connection, run_id)
        if result["status"] == "executing":
            await _execute_side_effects(connection, run_id)
            connection.commit()
            result = _serialize_run(connection, run_id)
    return result


@app.post("/compound-runs/{run_id}/mutations")
async def mutate_run(
    run_id: str,
    payload: RunMutation,
    x_atr_lab_token: str = Header(default=""),
    x_lab_role: str = Header(default=""),
) -> dict[str, object]:
    _auth(x_atr_lab_token)
    if x_lab_role != "admin":
        raise HTTPException(403, "Lab admin required for approval invalidation tests")
    with closing(_db()) as connection:
        run = connection.execute("SELECT * FROM compound_runs WHERE run_id=?", (run_id,)).fetchone()
        if run is None:
            raise HTTPException(404, "run not found")
        if run["status"] != "waiting_approval":
            raise HTTPException(409, "run is not waiting for approval")
        version = int(run["mutation_version"]) + 1
        policy_version = str(run["policy_version"])
        bundle_checksum = str(run["bundle_checksum"])
        image_digest = str(run["image_digest"])
        if payload.kind == "policy":
            policy_version = f"{policy_version}+mutation-{version}"
        elif payload.kind == "bundle":
            bundle_checksum = fingerprint({"previous": bundle_checksum, "version": version})
        elif payload.kind == "artifact":
            image_digest = f"sha256:mutated-{version}"
        content_fingerprint = fingerprint(
            {
                "previous": run["content_fingerprint"],
                "kind": payload.kind,
                "version": version,
                "policy": policy_version,
                "bundle": bundle_checksum,
                "image": image_digest,
            }
        )
        connection.execute(
            "UPDATE compound_runs SET policy_version=?,bundle_checksum=?,image_digest=?,content_fingerprint=?,mutation_version=?,updated_at=? WHERE run_id=?",
            (
                policy_version,
                bundle_checksum,
                image_digest,
                content_fingerprint,
                version,
                _now(),
                run_id,
            ),
        )
        _event(
            connection,
            run_id,
            "approval_invalidation",
            Decision("approval", "deny", f"APPROVAL_INVALIDATED_{payload.kind.upper()}"),
        )
        connection.commit()
        return _serialize_run(connection, run_id)


@app.get("/review-cases/assignments")
async def review_assignments(
    x_atr_lab_token: str = Header(default=""),
    x_lab_subject: str = Header(default=""),
) -> dict[str, object]:
    _auth(x_atr_lab_token)
    if x_lab_subject not in {"corpus-reviewer-a", "corpus-reviewer-b"}:
        raise HTTPException(403, "independent corpus reviewer required")
    with closing(_db()) as connection:
        rows = connection.execute(
            "SELECT case_id,boundary,rule_id,sample_fingerprint FROM corpus_review_cases WHERE case_id NOT IN (SELECT case_id FROM corpus_reviews WHERE reviewer=?) ORDER BY case_id",
            (x_lab_subject,),
        ).fetchall()
    return {"assignments": [dict(row) for row in rows], "blinded": True}


@app.post("/review-cases/{case_id}/reviews")
async def submit_review(
    case_id: str,
    payload: CorpusReview,
    x_atr_lab_token: str = Header(default=""),
    x_lab_subject: str = Header(default=""),
    x_lab_device_id: str = Header(default=""),
) -> dict[str, object]:
    _auth(x_atr_lab_token)
    identity = IDENTITIES.get(x_lab_subject)
    if (
        identity is None
        or identity["role"] != "corpus_reviewer"
        or identity["device"] != x_lab_device_id
    ):
        raise HTTPException(403, "reviewer identity or device binding failed")
    with closing(_db()) as connection:
        case = connection.execute(
            "SELECT case_id FROM corpus_review_cases WHERE case_id=?", (case_id,)
        ).fetchone()
        if case is None:
            raise HTTPException(404, "review case not found")
        try:
            connection.execute(
                "INSERT INTO corpus_reviews(case_id,reviewer,verdict,reason,created_at) VALUES(?,?,?,?,?)",
                (case_id, x_lab_subject, payload.verdict, payload.reason, _now()),
            )
            connection.commit()
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "reviewer already submitted this case") from exc
    return {"case_id": case_id, "reviewer": x_lab_subject, "status": "recorded"}


@app.get("/review-cases/results")
async def review_results(x_atr_lab_token: str = Header(default="")) -> dict[str, object]:
    _auth(x_atr_lab_token)
    with closing(_db()) as connection:
        rows = connection.execute(
            "SELECT c.case_id,c.boundary,c.rule_id,c.expected_verdict,r.reviewer,r.verdict FROM corpus_review_cases c JOIN corpus_reviews r ON r.case_id=c.case_id ORDER BY c.case_id,r.reviewer"
        ).fetchall()
    grouped: dict[str, list[dict[str, str]]] = {}
    metadata: dict[str, dict[str, str]] = {}
    for row in rows:
        grouped.setdefault(str(row["case_id"]), []).append(
            {"reviewer": str(row["reviewer"]), "verdict": str(row["verdict"])}
        )
        metadata[str(row["case_id"])] = {
            "boundary": str(row["boundary"]),
            "rule_id": str(row["rule_id"]),
            "expected_verdict": str(row["expected_verdict"]),
        }
    completed = []
    agreements = 0
    labels = ("true_positive", "false_positive", "acceptable_risk")
    reviewer_counts = {
        reviewer: {label: 0 for label in labels}
        for reviewer in ("corpus-reviewer-a", "corpus-reviewer-b")
    }
    for case_id, reviews in grouped.items():
        if len(reviews) != 2:
            continue
        agreed = reviews[0]["verdict"] == reviews[1]["verdict"]
        agreements += int(agreed)
        for review in reviews:
            reviewer_counts[review["reviewer"]][review["verdict"]] += 1
        completed.append(
            {"case_id": case_id, **metadata[case_id], "reviews": reviews, "agreed": agreed}
        )
    count = len(completed)
    observed = agreements / count if count else 0.0
    expected = 0.0
    if count:
        for label in labels:
            expected += (reviewer_counts["corpus-reviewer-a"][label] / count) * (
                reviewer_counts["corpus-reviewer-b"][label] / count
            )
    kappa = (
        (observed - expected) / (1 - expected)
        if count and expected < 1
        else (1.0 if count else 0.0)
    )
    return {
        "completed_cases": completed,
        "disagreements": [item for item in completed if not item["agreed"]],
        "metrics": {"completed": count, "agreement_rate": observed, "cohens_kappa": kappa},
    }


@app.delete("/review-cases/reviews")
async def reset_reviews(
    x_atr_lab_token: str = Header(default=""),
    x_lab_role: str = Header(default=""),
) -> dict[str, object]:
    _auth(x_atr_lab_token)
    if x_lab_role != "admin":
        raise HTTPException(403, "Lab admin required to reset review fixtures")
    with closing(_db()) as connection:
        deleted = connection.execute("DELETE FROM corpus_reviews").rowcount
        connection.commit()
    return {"deleted": deleted}
