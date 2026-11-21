#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from evidence_bundle import verify_evidence_bundle

from app.core.release_readiness import verify_human_review_attestation


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify v0.6 ATR release trust gates")
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--trusted-public-key", type=Path, required=True)
    parser.add_argument("--expected-key-sha256", required=True)
    parser.add_argument("--human-review-attestation", type=Path, required=True)
    args = parser.parse_args()
    evidence = verify_evidence_bundle(
        args.artifact_dir,
        trusted_public_key=args.trusted_public_key,
        expected_key_sha256=args.expected_key_sha256,
    )
    review = verify_human_review_attestation(
        args.human_review_attestation,
        corpus_paths=[
            Path("tests/corpus/atr_security.jsonl"),
            Path("tests/corpus/atr_adversarial_mutations.jsonl"),
        ],
    )
    result = {"release_ready": True, "evidence": evidence, "human_review": review}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
