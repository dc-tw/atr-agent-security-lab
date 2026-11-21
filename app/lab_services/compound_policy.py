from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

IDENTITIES: dict[str, dict[str, str]] = {
    "engineer-a": {"role": "wallet_devops", "device": "device-A", "resource": "wallet"},
    "engineer-b": {"role": "software_engineer", "device": "device-B", "resource": "application"},
    "engineer-c": {"role": "wallet_software_engineer", "device": "device-C", "resource": "wallet"},
    "security-reviewer": {
        "role": "security_reviewer",
        "device": "device-security",
        "resource": "review",
    },
    "operations-reviewer": {
        "role": "operations_reviewer",
        "device": "device-operations",
        "resource": "review",
    },
    "wallet-approver": {"role": "wallet_approver", "device": "device-wallet", "resource": "review"},
    "corpus-reviewer-a": {
        "role": "corpus_reviewer",
        "device": "device-review-a",
        "resource": "review",
    },
    "corpus-reviewer-b": {
        "role": "corpus_reviewer",
        "device": "device-review-b",
        "resource": "review",
    },
    "lab-admin": {"role": "lab_admin", "device": "device-admin", "resource": "admin"},
}

ARTIFACTS: dict[str, dict[str, Any]] = {
    "wallet-v1-signed": {
        "digest": "sha256:wallet-v1",
        "signed": True,
        "signer": "release-key-1",
        "builder": "trusted-builder",
        "provenance": True,
        "sbom": True,
        "attested": True,
    },
    "wallet-v1-tampered": {
        "digest": "sha256:tampered",
        "signed": True,
        "signer": "release-key-1",
        "builder": "trusted-builder",
        "provenance": True,
        "sbom": True,
        "attested": False,
        "integrity": False,
    },
    "wallet-v1-unsigned": {
        "digest": "sha256:unsigned",
        "signed": False,
        "signer": "",
        "builder": "trusted-builder",
        "provenance": True,
        "sbom": True,
        "attested": False,
    },
    "wallet-v1-revoked": {
        "digest": "sha256:revoked",
        "signed": True,
        "signer": "revoked-key",
        "builder": "trusted-builder",
        "provenance": True,
        "sbom": True,
        "attested": False,
    },
    "wallet-v1-unknown-builder": {
        "digest": "sha256:unknown-builder",
        "signed": True,
        "signer": "release-key-1",
        "builder": "unknown-builder",
        "provenance": True,
        "sbom": True,
        "attested": False,
    },
    "wallet-v1-injection": {
        "digest": "sha256:injection",
        "signed": True,
        "signer": "release-key-1",
        "builder": "trusted-builder",
        "provenance": True,
        "sbom": True,
        "attested": True,
        "fixture": "indirect-injection",
    },
}

ALLOWED_DESTINATIONS = {"treasury-cold", "customer-destination-1"}
MAX_AMOUNT = 1_000_000
POLICY_VERSION = "compound-policy-v1"
BUNDLE_CHECKSUM = hashlib.sha256(b"compound-lab-fixed-rules-v1").hexdigest()
COMPOUND_ATR_RULES = {
    "COMPOUND-CANARY": ("synthetic-canary", "credential-canary"),
    "COMPOUND-CREDENTIAL-EXFIL": ("export credential", "steal token", "dump secret"),
    "COMPOUND-REMOTE-CONTROL": ("remote control", "reverse shell", "command channel"),
    "COMPOUND-POLICY-BYPASS": ("bypass policy", "disable approval", "ignore admission"),
    "COMPOUND-MALICIOUS-DEPLOY": ("deploy attacker image", "replace signing service"),
}


@dataclass(frozen=True, slots=True)
class Decision:
    layer: str
    decision: str
    reason_code: str

    def as_dict(self) -> dict[str, str]:
        return {"layer": self.layer, "decision": self.decision, "reason_code": self.reason_code}


def fingerprint(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def evaluate_atr(*, synthetic_threat: bool, available: bool = True) -> Decision:
    if not available:
        return Decision("atr", "degraded", "ATR_FIXED_RULES_UNAVAILABLE")
    if synthetic_threat:
        return Decision("atr", "deny", "ATR_COMPOUND_THREAT_DETECTED")
    return Decision("atr", "allow", "ATR_CLEAR")


def scan_compound_atr(content: str) -> tuple[str, ...]:
    normalized = content.casefold()
    return tuple(
        rule_id
        for rule_id, phrases in COMPOUND_ATR_RULES.items()
        if any(phrase in normalized for phrase in phrases)
    )


def evaluate_iam(
    *,
    subject: str,
    device: str,
    target: str,
    token_claims: dict[str, Any],
    artifact_digest: str = "",
    available: bool = True,
) -> Decision:
    if not available:
        return Decision("iam", "degraded", "IAM_UNAVAILABLE")
    identity = IDENTITIES.get(subject)
    if identity is None:
        return Decision("iam", "deny", "IAM_UNKNOWN_SUBJECT")
    if identity["device"] != device:
        return Decision("iam", "deny", "IAM_DEVICE_MISMATCH")
    if target != identity["resource"] and identity["role"] != "lab_admin":
        return Decision("iam", "deny", "IAM_RESOURCE_SCOPE_MISMATCH")
    required = {"subject": subject, "device": device, "audience": "deployment", "scope": target}
    if artifact_digest:
        required["artifact_digest"] = artifact_digest
    if any(token_claims.get(key) != value for key, value in required.items()):
        return Decision("iam", "deny", "IAM_TOKEN_BINDING_MISMATCH")
    if not token_claims.get("valid", False):
        return Decision("iam", "deny", "IAM_TOKEN_EXPIRED_OR_REPLAYED")
    return Decision("iam", "allow", "IAM_AUTHORIZED")


def evaluate_supply_chain(
    *, artifact_id: str, image_digest: str, available: bool = True
) -> Decision:
    if not available:
        return Decision("supply_chain", "degraded", "ARTIFACT_REGISTRY_UNAVAILABLE")
    artifact = ARTIFACTS.get(artifact_id)
    if artifact is None or artifact["digest"] != image_digest:
        return Decision("supply_chain", "deny", "SUPPLY_DIGEST_MISMATCH")
    if artifact.get("integrity", True) is not True:
        return Decision("supply_chain", "deny", "SUPPLY_ARTIFACT_TAMPERED")
    if not artifact["signed"]:
        return Decision("supply_chain", "deny", "SUPPLY_UNSIGNED_ARTIFACT")
    if artifact["signer"] == "revoked-key":
        return Decision("supply_chain", "deny", "SUPPLY_REVOKED_SIGNER")
    if artifact["builder"] != "trusted-builder":
        return Decision("supply_chain", "deny", "SUPPLY_UNTRUSTED_BUILDER")
    if not artifact["provenance"] or not artifact["sbom"]:
        return Decision("supply_chain", "deny", "SUPPLY_METADATA_INCOMPLETE")
    return Decision("supply_chain", "allow", "SUPPLY_VERIFIED")


def evaluate_deployment(*, artifact_id: str, environment: str, available: bool = True) -> Decision:
    if not available:
        return Decision("deployment", "degraded", "DEPLOYMENT_ADMISSION_UNAVAILABLE")
    artifact = ARTIFACTS.get(artifact_id)
    if artifact is None or not artifact.get("attested"):
        return Decision("deployment", "deny", "DEPLOYMENT_WORKLOAD_NOT_ATTESTED")
    if environment == "production":
        return Decision("deployment", "approval", "DEPLOYMENT_DUAL_APPROVAL_REQUIRED")
    return Decision("deployment", "allow", "DEPLOYMENT_ADMITTED")


def evaluate_signing(
    *,
    operation: str,
    amount_atomic: str,
    destination: str,
    intent_id: str,
    workload_attested: bool,
    nonce_reused: bool = False,
    available: bool = True,
) -> Decision:
    if not available:
        return Decision("signing", "degraded", "SIGNING_POLICY_UNAVAILABLE")
    if not workload_attested:
        return Decision("signing", "deny", "SIGNING_WORKLOAD_NOT_ATTESTED")
    if operation == "delegation_authorization":
        return Decision("signing", "deny", "SIGNING_DELEGATION_DENIED")
    if operation in {"transfer", "contract_call"} and not intent_id:
        return Decision("signing", "deny", "SIGNING_CUSTOMER_INTENT_REQUIRED")
    if destination not in ALLOWED_DESTINATIONS:
        return Decision("signing", "deny", "SIGNING_UNKNOWN_DESTINATION")
    try:
        amount = int(amount_atomic)
    except ValueError:
        return Decision("signing", "deny", "SIGNING_INVALID_AMOUNT")
    if amount < 0 or amount > MAX_AMOUNT:
        return Decision("signing", "deny", "SIGNING_AMOUNT_EXCEEDED")
    if nonce_reused:
        return Decision("signing", "deny", "SIGNING_NONCE_BURST")
    return Decision("signing", "approval", "SIGNING_WALLET_APPROVAL_REQUIRED")
