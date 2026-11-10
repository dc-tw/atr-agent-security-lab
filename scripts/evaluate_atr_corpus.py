import json
from collections import Counter
from pathlib import Path

from app.core.config import get_settings
from app.core.threat_detection import ThreatDetector


def main() -> None:
    detector = ThreatDetector.from_settings(get_settings())
    corpus = Path("tests/corpus/atr_security.jsonl")
    counts: Counter[str] = Counter()
    misses = []
    for line in corpus.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        case = json.loads(line)
        field = {
            "llm_input": "user_input",
            "tool_response": "tool_response",
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
        if expected != detected:
            misses.append({"id": case["id"], "bucket": bucket})
    precision = counts["tp"] / max(1, counts["tp"] + counts["fp"])
    recall = counts["tp"] / max(1, counts["tp"] + counts["fn"])
    print(
        json.dumps(
            {
                "counts": counts,
                "precision": precision,
                "recall": recall,
                "misses": misses,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
