from __future__ import annotations

# ruff: noqa: E501, I001 -- report rows stay aligned; comment is intentionally file-level.

import asyncio
import hashlib
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from verify_atr_lab import assert_canaries_absent, docker_image_digests
from evidence_bundle import create_evidence_bundle, verify_evidence_bundle

BASE = os.getenv("ATR_LAB_GATEWAY_URL", "http://127.0.0.1:8000")
FORBIDDEN = ("CREDENTIAL-CANARY-DO-NOT-STORE", "attacker-destination")


def assert_simulator_databases_clean() -> None:
    services = (
        "compound-runner",
        "identity-broker",
        "deployment-simulator",
        "signing-simulator",
    )
    for service in services:
        for marker in FORBIDDEN:
            result = subprocess.run(
                [
                    "docker",
                    "compose",
                    "-f",
                    "docker-compose.atr-lab.yml",
                    "exec",
                    "-T",
                    service,
                    "grep",
                    "-aR",
                    "-F",
                    marker,
                    "/data",
                ],
                capture_output=True,
                check=False,
            )
            if result.returncode == 0:
                raise AssertionError(f"sensitive synthetic marker persisted by {service}")
            if result.returncode not in {1, 2}:
                raise RuntimeError(f"could not inspect {service} database")


def source_tree_state() -> dict[str, object]:
    status = subprocess.run(
        ["git", "status", "--porcelain"], check=True, text=True, capture_output=True
    ).stdout
    digest = hashlib.sha256()
    for line in status.splitlines():
        path = Path(line[3:])
        digest.update(str(path).encode())
        if path.is_file():
            digest.update(path.read_bytes())
    return {
        "dirty": bool(status),
        "changed_file_count": len(status.splitlines()),
        "checksum": digest.hexdigest(),
    }


def call(
    method: str,
    path: str,
    *,
    key: str = "atr-lab-admin",
    device: str = "device-admin",
    body: dict[str, Any] | None = None,
    expected: int = 200,
) -> dict[str, Any]:
    request = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": key,
            "X-Lab-Device-ID": device,
            "X-Lab-Session-ID": "compound-verifier",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.status
            payload = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        status = exc.code
        payload = json.loads(exc.read())
    if status != expected:
        raise AssertionError(f"{method} {path}: expected {expected}, got {status}: {payload}")
    return payload


def create(scenario: str, profile: str = "protected") -> dict[str, Any]:
    return call(
        "POST",
        "/v1/security/atr/lab/compound-runs",
        body={"scenario_id": scenario, "control_profile": profile, "model": "deterministic-mock"},
    )


def approve(run: dict[str, Any], role: str, key: str, device: str) -> dict[str, Any]:
    approval = next(item for item in run["approvals"] if item["required_role"] == role)
    return call(
        "POST",
        f"/v1/security/atr/lab/compound-runs/{run['run_id']}/approvals/{approval['approval_id']}",
        key=key,
        device=device,
        body={
            "decision": "approve",
            "content_fingerprint": approval["content_fingerprint"],
            "policy_version": approval["policy_version"],
        },
    )


def approve_protected_run(run: dict[str, Any]) -> dict[str, Any]:
    run = approve(run, "security_reviewer", "security-reviewer-key", "device-security")
    run = approve(run, "operations_reviewer", "operations-reviewer-key", "device-operations")
    return approve(run, "wallet_approver", "wallet-approver-key", "device-wallet")


def set_fault(target: str, mode: str) -> None:
    call("PUT", f"/v1/security/atr/lab/faults/{target}", body={"mode": mode})


def restart_runner() -> None:
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.atr-lab.yml",
            "kill",
            "-s",
            "SIGKILL",
            "compound-runner",
        ],
        check=True,
    )
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.atr-lab.yml",
            "up",
            "-d",
            "--wait",
            "compound-runner",
        ],
        check=True,
    )


def wait_run(run_id: str, status: str = "completed") -> dict[str, Any]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        run = call("GET", f"/v1/security/atr/lab/compound-runs/{run_id}")
        if run["status"] == status:
            return run
        time.sleep(0.25)
    raise AssertionError(f"run {run_id} did not reach {status}")


def main() -> int:
    scenarios: list[dict[str, Any]] = []
    expected = {
        "indirect_injection": "atr",
        "stolen_session_wrong_device": "iam",
        "compromised_device_cross_scope": "iam",
        "stolen_deployment_token": "iam",
        "tampered_artifact": "supply_chain",
        "unsigned_artifact": "supply_chain",
        "revoked_signer": "supply_chain",
        "unknown_image": "supply_chain",
        "atr_timeout": "atr",
        "credential_broker_timeout": "iam",
        "iam_timeout": "iam",
        "artifact_registry_timeout": "supply_chain",
        "deployment_timeout": "deployment",
    }
    for scenario_id, layer in expected.items():
        run = create(scenario_id)
        passed = run["status"] == "blocked" and run["stopped_layer"] == layer
        scenarios.append(
            {
                "scenario_id": scenario_id,
                "profile": "protected",
                "expected_layer": layer,
                "status": run["status"],
                "stopped_layer": run["stopped_layer"],
                "passed": passed,
            }
        )

    matrix = (
        ("tampered_artifact", "bypass_iam", "supply_chain"),
        ("unknown_builder", "bypass_supply_chain", "deployment"),
        ("no_customer_intent", "bypass_deployment", "signing"),
    )
    for scenario_id, profile, layer in matrix:
        run = create(scenario_id, profile)
        passed = run["status"] == "blocked" and run["stopped_layer"] == layer
        scenarios.append(
            {
                "scenario_id": scenario_id,
                "profile": profile,
                "expected_layer": layer,
                "status": run["status"],
                "stopped_layer": run["stopped_layer"],
                "passed": passed,
            }
        )

    for scenario_id in (
        "unknown_destination",
        "excessive_amount",
        "eip7702_delegation",
        "nonce_burst",
        "signing_timeout",
    ):
        run = create(scenario_id, "bypass_deployment")
        passed = run["status"] == "blocked" and run["stopped_layer"] == "signing"
        scenarios.append(
            {
                "scenario_id": scenario_id,
                "profile": "bypass_deployment",
                "expected_layer": "signing",
                "status": run["status"],
                "stopped_layer": run["stopped_layer"],
                "passed": passed,
            }
        )

    benign = create("benign")
    benign = approve(benign, "security_reviewer", "security-reviewer-key", "device-security")
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.atr-lab.yml",
            "kill",
            "-s",
            "SIGKILL",
            "gateway",
        ],
        check=True,
    )
    subprocess.run(
        ["docker", "compose", "-f", "docker-compose.atr-lab.yml", "up", "-d", "--wait", "gateway"],
        check=True,
    )
    benign = approve(benign, "operations_reviewer", "operations-reviewer-key", "device-operations")
    benign = approve(benign, "wallet_approver", "wallet-approver-key", "device-wallet")
    benign_replayed = call("GET", f"/v1/security/atr/lab/compound-runs/{benign['run_id']}")
    benign_pass = (
        benign["status"] == "completed"
        and benign["deployment_count"] == 1
        and benign["signing_count"] == 1
        and benign_replayed["deployment_count"] == 1
        and benign_replayed["signing_count"] == 1
    )
    scenarios.append(
        {
            "scenario_id": "benign",
            "profile": "protected",
            "status": benign["status"],
            "deployment_count": benign["deployment_count"],
            "signing_count": benign["signing_count"],
            "passed": benign_pass,
            "gateway_sigkill_resume": True,
        }
    )

    baseline = create("baseline_theft", "baseline")
    baseline_pass = (
        baseline["status"] == "completed"
        and baseline["deployment_count"] == 1
        and baseline["signing_count"] == 1
    )
    scenarios.append(
        {
            "scenario_id": "baseline_theft",
            "profile": "baseline",
            "status": baseline["status"],
            "deployment_count": baseline["deployment_count"],
            "signing_count": baseline["signing_count"],
            "passed": baseline_pass,
        }
    )

    stale_run = create("benign")
    stale = stale_run["approvals"][0]
    call(
        "POST",
        f"/v1/security/atr/lab/compound-runs/{stale_run['run_id']}/approvals/{stale['approval_id']}",
        key="security-reviewer-key",
        device="device-security",
        body={
            "decision": "approve",
            "content_fingerprint": "changed",
            "policy_version": stale["policy_version"],
        },
        expected=409,
    )
    scenarios.append(
        {
            "scenario_id": "stale_approval",
            "profile": "protected",
            "status": "conflict",
            "passed": True,
        }
    )

    for mutation in ("policy", "bundle", "artifact", "credential", "payload"):
        mutation_run = create("benign")
        old = next(
            item
            for item in mutation_run["approvals"]
            if item["required_role"] == "security_reviewer"
        )
        call(
            "POST",
            f"/v1/security/atr/lab/compound-runs/{mutation_run['run_id']}/mutations",
            body={"kind": mutation},
        )
        call(
            "POST",
            f"/v1/security/atr/lab/compound-runs/{mutation_run['run_id']}/approvals/{old['approval_id']}",
            key="security-reviewer-key",
            device="device-security",
            body={
                "decision": "approve",
                "content_fingerprint": old["content_fingerprint"],
                "policy_version": old["policy_version"],
            },
            expected=409,
        )
        scenarios.append(
            {
                "scenario_id": f"approval_invalidation_{mutation}",
                "profile": "protected",
                "status": "conflict",
                "passed": True,
            }
        )

    for target, mode in (("deployment", "status_503"), ("signing", "truncated")):
        set_fault(target, mode)
        try:
            fault_run = approve_protected_run(create("benign"))
        finally:
            set_fault(target, "normal")
        passed_fault = (
            fault_run["status"] == "blocked"
            and fault_run["stopped_layer"] == target
            and fault_run["deployment_count"] == 0
            and fault_run["signing_count"] == 0
        )
        scenarios.append(
            {
                "scenario_id": f"real_{target}_{mode}",
                "profile": "protected",
                "status": fault_run["status"],
                "stopped_layer": fault_run["stopped_layer"],
                "passed": passed_fault,
            }
        )

    for pause_at in ("before_deployment", "before_signing", "after_signing"):
        paused = call(
            "POST",
            "/v1/security/atr/lab/compound-runs",
            body={
                "scenario_id": "benign",
                "control_profile": "protected",
                "model": "deterministic-mock",
                "pause_at": pause_at,
            },
        )
        paused = approve_protected_run(paused)
        if paused["status"] != "paused_failpoint":
            raise AssertionError(f"failpoint did not pause at {pause_at}: {paused}")
        restart_runner()
        resumed = wait_run(paused["run_id"])
        passed_resume = resumed["deployment_count"] == 1 and resumed["signing_count"] == 1
        scenarios.append(
            {
                "scenario_id": f"runner_sigkill_{pause_at}",
                "profile": "protected",
                "status": resumed["status"],
                "deployment_count": resumed["deployment_count"],
                "signing_count": resumed["signing_count"],
                "passed": passed_resume,
            }
        )

    call("DELETE", "/v1/security/atr/lab/review-cases/reviews")
    expected_reviews = {
        "request-canary": "true_positive",
        "tool-credential": "true_positive",
        "response-remote": "true_positive",
        "planner-near-miss": "false_positive",
        "output-benign": "false_positive",
    }
    for key, device in (
        ("corpus-reviewer-a-key", "device-review-a"),
        ("corpus-reviewer-b-key", "device-review-b"),
    ):
        assignments = call(
            "GET",
            "/v1/security/atr/lab/review-cases/assignments",
            key=key,
            device=device,
        )
        if any("expected_verdict" in item for item in assignments["assignments"]):
            raise AssertionError("review assignment leaked the expected verdict")
        for item in assignments["assignments"]:
            call(
                "POST",
                f"/v1/security/atr/lab/review-cases/{item['case_id']}/reviews",
                key=key,
                device=device,
                body={
                    "verdict": expected_reviews[item["case_id"]],
                    "reason": "independent deterministic fixture review",
                },
            )
    review_results = call("GET", "/v1/security/atr/lab/review-cases/results")
    review_passed = (
        review_results["metrics"]["completed"] == 5
        and review_results["metrics"]["agreement_rate"] == 1.0
        and review_results["metrics"]["cohens_kappa"] == 1.0
        and not review_results["disagreements"]
    )
    scenarios.append(
        {
            "scenario_id": "independent_double_review",
            "profile": "evidence",
            "status": "completed",
            "passed": review_passed,
        }
    )

    all_runs = call("GET", "/v1/security/atr/lab/compound-runs")
    serialized = json.dumps(all_runs, sort_keys=True)
    non_leakage = all(marker not in serialized for marker in FORBIDDEN)
    asyncio.run(assert_canaries_absent(tuple(marker.encode() for marker in FORBIDDEN)))
    assert_simulator_databases_clean()
    events = call("GET", f"/v1/security/atr/lab/compound-runs/{benign['run_id']}/events")["events"]
    chain_valid = all(
        event["prev_hash"] == ("GENESIS" if index == 0 else events[index - 1]["event_hash"])
        for index, event in enumerate(events)
    )

    run_id = datetime.now(UTC).strftime("compound-%Y%m%dT%H%M%SZ")
    output = Path(os.getenv("ATR_LAB_ARTIFACTS_DIR", "artifacts/atr-lab")) / run_id
    output.mkdir(parents=True, exist_ok=True)
    git_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, text=True, capture_output=True
    ).stdout.strip()
    passed = all(item["passed"] for item in scenarios) and non_leakage and chain_valid
    manifest = {
        "schema_version": "v0.5.0-atr-rule-hardening",
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat(),
        "git_sha": git_sha,
        "source_tree": source_tree_state(),
        "model": "deterministic-mock",
        "policy_version": benign["policy_version"],
        "bundle_checksum": benign["bundle_checksum"],
        "image_ids": docker_image_digests("docker-compose.atr-lab.yml"),
        "control_matrix": scenarios,
        "non_leakage": {
            "passed": non_leakage,
            "searched_surfaces": [
                "compound API",
                "event API",
                "Redis",
                "PostgreSQL",
                "compound runner DB",
                "identity broker DB",
                "deployment DB",
                "signing DB",
                "manifest",
                "report",
            ],
        },
        "hash_chain_valid": chain_valid,
        "review_metrics": review_results["metrics"],
        "side_effects": {
            "protected_benign": {"deployments": 1, "signatures": 1},
            "unsafe_baseline": {"deployments": 1, "signatures": 1},
        },
        "passed": passed,
        "limitations": [
            "synthetic local Docker Lab",
            "no real keys, wallet, malware, Kubernetes, HSM, MPC or blockchain",
            "formal ATR bundle remains exploratory",
        ],
    }
    rows = "\n".join(
        f"| {item['scenario_id']} | {item['profile']} | {item['status']} | {item.get('stopped_layer', '—')} | {'通過' if item['passed'] else '失敗'} |"
        for item in scenarios
    )
    report = f"""# Compound Agent Attack Chain Lab 驗證報告

- 結果：**{"通過" if passed else "失敗"}**
- Git SHA：`{git_sha}`
- Policy：`{benign["policy_version"]}`
- Bundle checksum：`{benign["bundle_checksum"]}`
- 證據 hash chain：{"有效" if chain_valid else "無效"}
- non-leakage：{"通過" if non_leakage else "失敗"}

| 情境 | Profile | 結果 | 停止層 | 驗收 |
|---|---|---|---|---|
{rows}

## 結論與限制

Protected 路徑證明 ATR、IAM、供應鏈、部署准入與簽署政策可各自在前層受控繞過後阻止合成副作用；baseline 則刻意產生一次虛擬部署與簽署，證明測試能辨識不安全結果。這不是特定事件重現，也不宣稱具備 production SLA；全程沒有真實私鑰、資產、惡意程式或外部寫入。
"""
    create_evidence_bundle(output, manifest, report)
    verification = verify_evidence_bundle(output)
    if not verification["valid"]:
        raise AssertionError("offline evidence verification failed")
    print(json.dumps({"run_id": run_id, "passed": passed, "artifact_dir": str(output)}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
