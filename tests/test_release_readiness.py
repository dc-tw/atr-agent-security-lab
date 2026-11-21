import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.release_readiness import (
    corpus_digest,
    reviewer_signature_payload,
    verify_human_review_attestation,
)


def _reviewer(key: Ed25519PrivateKey, digest: str, cases: int) -> dict[str, object]:
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    verdicts = hashlib.sha256(public_pem + b"verdicts").hexdigest()
    completed_at = "2026-11-21T00:00:00Z"
    payload = reviewer_signature_payload(
        corpus_sha256=digest,
        completed_cases=cases,
        verdicts_sha256=verdicts,
        completed_at=completed_at,
    )
    return {
        "review_kind": "human",
        "completed_cases": cases,
        "verdicts_sha256": verdicts,
        "completed_at": completed_at,
        "public_key_pem": public_pem.decode(),
        "signature": base64.b64encode(key.sign(payload)).decode(),
    }


def test_release_review_requires_two_signed_independent_humans(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text('{"id":"one"}\n{"id":"two"}\n')
    digest, cases = corpus_digest([corpus])
    evidence = {
        "schema_version": "atr-human-review-v1",
        "corpus_sha256": digest,
        "reviewers": [
            _reviewer(Ed25519PrivateKey.generate(), digest, cases),
            _reviewer(Ed25519PrivateKey.generate(), digest, cases),
        ],
        "agreement": {"cohens_kappa": 1, "disagreements_resolved": True},
    }
    path = tmp_path / "reviews.json"
    path.write_text(json.dumps(evidence))
    result = verify_human_review_attestation(path, corpus_paths=[corpus])
    assert result["reviewer_count"] == 2


def test_release_review_rejects_synthetic_or_duplicate_reviewer(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text('{"id":"one"}\n')
    digest, cases = corpus_digest([corpus])
    key = Ed25519PrivateKey.generate()
    reviewer = _reviewer(key, digest, cases)
    reviewer["review_kind"] = "synthetic"
    path = tmp_path / "reviews.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "atr-human-review-v1",
                "corpus_sha256": digest,
                "reviewers": [reviewer, reviewer],
                "agreement": {"cohens_kappa": 1, "disagreements_resolved": True},
            }
        )
    )
    with pytest.raises(ValueError, match="synthetic"):
        verify_human_review_attestation(path, corpus_paths=[corpus])
