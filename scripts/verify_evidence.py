from __future__ import annotations

import argparse
import json
from pathlib import Path

from evidence_bundle import verify_evidence_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a v0.5 ATR Lab evidence bundle offline")
    parser.add_argument("artifact_dir", type=Path)
    parser.add_argument("--trusted-public-key", type=Path)
    parser.add_argument("--expected-key-sha256")
    args = parser.parse_args()
    try:
        result = verify_evidence_bundle(
            args.artifact_dir,
            trusted_public_key=args.trusted_public_key,
            expected_key_sha256=args.expected_key_sha256,
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
