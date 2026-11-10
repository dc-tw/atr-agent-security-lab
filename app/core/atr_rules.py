from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from app.core.threat_detection import SEVERITY_RANK, ThreatDetector


def rule_bundle_manifest(detector: ThreatDetector, source_path: str) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    errors: list[str] = []
    for rule in detector.engine.rules:
        rule_id = str(rule.id)
        if rule_id in seen:
            errors.append(f"duplicate rule ID: {rule_id}")
        seen.add(rule_id)
        severity = str(rule.severity)
        if severity not in SEVERITY_RANK:
            errors.append(f"{rule_id}: invalid severity {severity}")
        conditions = [
            {
                "field": str(condition.field),
                "operator": str(condition.operator),
                "value": str(condition.value),
            }
            for condition in rule.conditions
        ]
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
