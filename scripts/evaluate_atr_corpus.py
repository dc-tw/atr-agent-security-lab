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
        for rule_id in matched_rule_ids:
            per_rule[rule_id]["reviewed_samples"] += 1
            per_rule[rule_id]["false_positives" if not expected else "true_positives"] += 1
        if expected != detected:
            misses.append({"id": case["id"], "bucket": bucket})
    precision = counts["tp"] / max(1, counts["tp"] + counts["fp"])
    recall = counts["tp"] / max(1, counts["tp"] + counts["fn"])
    rule_stats = {
        rule_id: {
            **stat,
            "fp_rate": stat["false_positives"] / max(1, stat["reviewed_samples"]),
        }
        for rule_id, stat in sorted(per_rule.items())
    }
    print(
        json.dumps(
            {
                "counts": counts,
                "precision": precision,
                "recall": recall,
                "misses": misses,
                "per_rule": rule_stats,
                "rule_health": manifest["validation_report"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
