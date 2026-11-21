import json
from collections import Counter, defaultdict
from pathlib import Path

from app.core.atr_rules import load_rule_bundle
from app.core.config import get_settings


def main() -> None:
    detector, manifest = load_rule_bundle(get_settings())
    corpus = Path("tests/corpus/atr_security.jsonl")
    counts: Counter[str] = Counter()
    per_rule: dict[str, Counter[str]] = defaultdict(Counter)
    misses = []
    for line in corpus.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        case = json.loads(line)
        field = {
            "request_input": "user_input",
            "llm_input": "user_input",
            "planner_output": "planner_output",
            "tool_call": "tool_args",
            "tool_response": "tool_response",
            "model_output": "agent_output",
            "llm_output": "agent_output",
        }[case["boundary"]]
        scan = detector.scan(
            case["content"],
            event_type=case["boundary"],
            location=f"corpus:{case['id']}",
            fields={field: case["content"]},
        )
        expected = case["label"] == "adversarial"
        detected = bool(scan.findings)
        bucket = ("tp" if expected else "fp") if detected else ("fn" if expected else "tn")
        counts[bucket] += 1
        matched_rule_ids = {str(item["rule_id"]) for item in scan.findings}
        expected_rule_ids = set(case.get("expected_rule_ids", []))
        target_rule_ids = set(case.get("target_rule_ids", [])) | expected_rule_ids
        for rule_id in target_rule_ids:
            per_rule[rule_id]["reviewed_samples"] += 1
            if rule_id in matched_rule_ids and rule_id in expected_rule_ids:
                per_rule[rule_id]["true_positives"] += 1
            elif rule_id in matched_rule_ids:
                per_rule[rule_id]["false_positives"] += 1
            elif rule_id in expected_rule_ids:
                per_rule[rule_id]["false_negatives"] += 1
            else:
                per_rule[rule_id]["true_negatives"] += 1
        if expected != detected:
            misses.append({"id": case["id"], "bucket": bucket})
    precision = counts["tp"] / max(1, counts["tp"] + counts["fp"])
    recall = counts["tp"] / max(1, counts["tp"] + counts["fn"])
    rule_stats = {
        rule_id: {
            **stat,
            "fp_rate": stat["false_positives"] / max(1, stat["reviewed_samples"]),
            "fn_rate": stat["false_negatives"] / max(1, stat["reviewed_samples"]),
        }
        for rule_id, stat in sorted(per_rule.items())
    }
    candidate_ids = {
        "ATR-2026-00290",
        *(rule_id for rule_id in per_rule if rule_id.startswith("ATR-GW-")),
    }
    promotion_failures = [
        rule_id
        for rule_id in sorted(candidate_ids)
        if rule_stats.get(rule_id, {}).get("reviewed_samples", 0) < 2
        or rule_stats.get(rule_id, {}).get("false_positives", 0) > 0
        or rule_stats.get(rule_id, {}).get("false_negatives", 0) > 0
    ]
    print(
        json.dumps(
            {
                "counts": counts,
                "precision": precision,
                "recall": recall,
                "misses": misses,
                "per_rule": rule_stats,
                "candidate_promotion_failures": promotion_failures,
                "rule_health": manifest["validation_report"],
            },
            indent=2,
        )
    )
    if misses or promotion_failures or not manifest["validation_report"]["blocking_eligible"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
