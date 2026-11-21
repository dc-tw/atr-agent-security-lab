#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from app.core.atr_rules import load_rule_bundle
from app.core.config import get_settings


def main() -> int:
    detector, manifest = load_rule_bundle(get_settings())
    path = Path("tests/corpus/atr_adversarial_mutations.jsonl")
    totals: Counter[str] = Counter()
    techniques: dict[str, Counter[str]] = defaultdict(Counter)
    failures: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        case = json.loads(line)
        scan = detector.scan(
            case["content"],
            event_type=case["boundary"],
            location=f"mutation:{case['id']}",
        )
        matched = {str(item["rule_id"]) for item in scan.findings}
        missing = sorted(set(case.get("expected_rule_ids", [])) - matched)
        forbidden = sorted(set(case.get("forbidden_rule_ids", [])) & matched)
        passed = not missing and not forbidden
        totals["passed" if passed else "failed"] += 1
        techniques[case["technique"]]["passed" if passed else "failed"] += 1
        if not passed:
            failures.append(
                {
                    "id": case["id"],
                    "missing": missing,
                    "forbidden": forbidden,
                    "matched": sorted(matched),
                }
            )
    result = {
        "cases": sum(totals.values()),
        "passed": totals["passed"],
        "failed": totals["failed"],
        "techniques": {key: value for key, value in sorted(techniques.items())},
        "failures": failures,
        "bundle_checksum": manifest["checksum"],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
