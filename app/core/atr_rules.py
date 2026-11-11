from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import regex as regex_module

from app.core.threat_detection import SEVERITY_RANK, ThreatDetector


def rule_bundle_manifest(detector: ThreatDetector, source_path: str) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    errors: list[str] = []
    invalid_conditions: list[dict[str, Any]] = []
    failed = set(getattr(detector.engine, "_failed_regexes", set()))
    for rule in detector.engine.rules:
        rule_id = str(rule.id)
        if rule_id in seen:
            errors.append(f"duplicate rule ID: {rule_id}")
        seen.add(rule_id)
        severity = str(rule.severity)
        if severity not in SEVERITY_RANK:
            errors.append(f"{rule_id}: invalid severity {severity}")
        conditions = []
        for index, condition in enumerate(rule.conditions):
            condition_record = {
                "field": str(condition.field),
                "operator": str(condition.operator),
                "value": str(condition.value),
            }
            conditions.append(condition_record)
            if condition_record["operator"] == "regex":
                try:
                    re.compile(condition_record["value"])
                except re.error:
                    try:
                        regex_module.compile(condition_record["value"])
                    except regex_module.error as exc:
                        invalid_conditions.append(
                            {
                                "rule_id": rule_id,
                                "condition_index": index,
                                "error": str(exc),
                            }
                        )
            if (rule_id, index) in failed and not any(
                item["rule_id"] == rule_id and item["condition_index"] == index
                for item in invalid_conditions
            ):
                invalid_conditions.append(
                    {
                        "rule_id": rule_id,
                        "condition_index": index,
                        "error": "pyatr could not compile this condition",
                    }
                )
        rules.append(
            {
                "rule_id": rule_id,
                "title": str(rule.title),
                "severity": severity,
                "status": str(rule.status),
                "tags": dict(rule.tags),
                "condition_count": len(conditions),
                "conditions": conditions,
            }
        )
    invalid_rule_ids = sorted({item["rule_id"] for item in invalid_conditions})
    if invalid_rule_ids:
        detector.engine._rules = [
            rule for rule in detector.engine.rules if str(rule.id) not in invalid_rule_ids
        ]
        for rule_id in invalid_rule_ids:
            detector.engine._compiled.pop(rule_id, None)
        rules = [rule for rule in rules if rule["rule_id"] not in invalid_rule_ids]
        detector.rule_count = len(rules)
    rules.sort(key=lambda item: item["rule_id"])
    canonical = json.dumps(rules, sort_keys=True, separators=(",", ":"))
    checksum = hashlib.sha256(canonical.encode()).hexdigest()
    detector.bundle_checksum = checksum
    version_path = Path(source_path) / "VERSION" if source_path else None
    version = checksum[:12]
    if version_path and version_path.is_file():
        candidate = version_path.read_text(encoding="utf-8").strip()
        if candidate and len(candidate) <= 128:
            version = candidate
    return {
        "version": version,
        "checksum": checksum,
        "source_path": source_path or "pyatr://default",
        "rule_count": len(rules),
        "validation_report": {
            "valid": not errors and len(rules) > 0,
            "errors": errors,
            "degraded": bool(invalid_conditions),
            "invalid_conditions": invalid_conditions,
            "invalid_rule_ids": invalid_rule_ids,
            "blocking_eligible": not invalid_conditions,
        },
        "rules": rules,
    }


def load_rule_bundle(
    settings: Any, source_path: str | None = None
) -> tuple[ThreatDetector, dict[str, Any]]:
    path = settings.atr_rules_dir if source_path is None else source_path
    if path and not Path(path).is_dir():
        raise ValueError(f"ATR rules directory does not exist: {path}")
    detector = ThreatDetector(
        enabled=settings.atr_enabled,
        blocking=settings.atr_blocking,
        min_severity=settings.atr_min_severity,
        block_severity=settings.atr_block_severity,
        max_content_chars=settings.atr_max_content_chars,
        rules_dir=path,
        blocking_rule_ids=settings.atr_blocking_rule_ids,
        blocking_excluded_rule_ids=settings.atr_blocking_excluded_rule_ids,
        scan_retries=settings.atr_scan_retries,
        fingerprint_secret=settings.atr_fingerprint_secret,
    )
    manifest = rule_bundle_manifest(detector, path)
    if not manifest["validation_report"]["valid"]:
        raise ValueError(
            "ATR rule bundle validation failed: "
            + "; ".join(manifest["validation_report"]["errors"])
        )
    return detector, manifest
