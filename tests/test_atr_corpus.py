import json
from pathlib import Path

from app.core.config import Settings
from app.core.threat_detection import ThreatDetector


def _cases() -> list[dict[str, str]]:
    path = Path(__file__).parent / "corpus" / "atr_security.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_security_corpus_has_no_known_false_negatives_or_false_positives() -> None:
    detector = ThreatDetector.from_settings(Settings(atr_min_severity="medium"))
    failures = []
    for case in _cases():
        boundary = case["boundary"]
        field = {
            "request_input": "user_input",
            "llm_input": "user_input",
            "planner_output": "planner_output",
            "tool_call": "tool_args",
            "tool_response": "tool_response",
            "model_output": "agent_output",
            "llm_output": "agent_output",
        }[boundary]
        scan = detector.scan(
            case["content"],
            event_type=boundary,
            location=f"corpus:{case['id']}",
            fields={field: case["content"]},
        )
        detected = bool(scan.findings)
        expected = case["label"] == "adversarial"
        if detected != expected:
            failures.append(
                {
                    "id": case["id"],
                    "expected": expected,
                    "detected": detected,
                    "rules": [finding["rule_id"] for finding in scan.findings],
                }
            )
    assert not failures, failures
