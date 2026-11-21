from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def corpus_digest(paths: list[Path]) -> tuple[str, int]:
    digest = hashlib.sha256()
    cases = 0
    for path in sorted(paths, key=lambda item: item.as_posix()):
        content = path.read_bytes()
        digest.update(path.name.encode())
        digest.update(b"\0")
        digest.update(content)
        cases += sum(bool(line.strip()) for line in content.splitlines())
    return digest.hexdigest(), cases


def reviewer_signature_payload(
    *, corpus_sha256: str, completed_cases: int, verdicts_sha256: str, completed_at: str
) -> bytes:
    return json.dumps(
        {
            "completed_at": completed_at,
            "completed_cases": completed_cases,
            "corpus_sha256": corpus_sha256,
            "verdicts_sha256": verdicts_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def verify_human_review_attestation(
    path: Path,
    *,
    corpus_paths: list[Path],
    minimum_kappa: float = 0.8,
) -> dict[str, Any]:
    evidence = json.loads(path.read_text(encoding="utf-8"))
    expected_digest, expected_cases = corpus_digest(corpus_paths)
    if evidence.get("schema_version") != "atr-human-review-v1":
        raise ValueError("unsupported human review attestation schema")
    if evidence.get("corpus_sha256") != expected_digest:
        raise ValueError("human review corpus digest is stale")
    reviewers = evidence.get("reviewers")
    if not isinstance(reviewers, list) or len(reviewers) < 2:
        raise ValueError("two independent human reviewer attestations are required")
    fingerprints: set[str] = set()
    for reviewer in reviewers:
        if reviewer.get("review_kind") != "human":
            raise ValueError("synthetic reviewer evidence is not release eligible")
        completed_cases = int(reviewer.get("completed_cases", 0))
        verdicts_sha256 = str(reviewer.get("verdicts_sha256", ""))
        completed_at = str(reviewer.get("completed_at", ""))
        if completed_cases != expected_cases or not _SHA256.fullmatch(verdicts_sha256):
            raise ValueError("reviewer evidence does not cover the complete corpus")
        public_pem = str(reviewer.get("public_key_pem", "")).encode()
        key = serialization.load_pem_public_key(public_pem)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("reviewer attestation key must be Ed25519")
        fingerprint = hashlib.sha256(public_pem).hexdigest()
        if fingerprint in fingerprints:
            raise ValueError("reviewers must use independent keys")
        fingerprints.add(fingerprint)
        payload = reviewer_signature_payload(
            corpus_sha256=expected_digest,
            completed_cases=completed_cases,
            verdicts_sha256=verdicts_sha256,
            completed_at=completed_at,
        )
        try:
            signature = base64.b64decode(str(reviewer.get("signature", "")), validate=True)
            key.verify(signature, payload)
        except (binascii.Error, InvalidSignature) as exc:
            raise ValueError("human reviewer attestation signature is invalid") from exc
    agreement = evidence.get("agreement", {})
    if float(agreement.get("cohens_kappa", -1)) < minimum_kappa:
        raise ValueError("human reviewer agreement is below the release threshold")
    if not agreement.get("disagreements_resolved"):
        raise ValueError("human review disagreements must be resolved")
    return {
        "valid": True,
        "corpus_sha256": expected_digest,
        "reviewed_cases_per_reviewer": expected_cases,
        "reviewer_count": len(fingerprints),
        "cohens_kappa": float(agreement["cohens_kappa"]),
        "reviewer_key_sha256": sorted(fingerprints),
    }
