from __future__ import annotations

# ruff: noqa: E501 -- security regexes remain whole for checksum review and upstream comparison.
import hashlib
from dataclasses import replace
from typing import Any

from pyatr import ATREngine
from pyatr.types import ATRRule, Condition

BROKEN_DIVERGENCE_PATTERN = r"(?:(?:\w+\s+){40,})\1{3,}"
FIXED_DIVERGENCE_PATTERN = r"(?i)\b(\w{1,30})(?:\s+\1){39,}\b"


def _rule(
    rule_id: str,
    title: str,
    category: str,
    pattern: str,
    *,
    severity: str = "critical",
) -> ATRRule:
    return ATRRule(
        id=rule_id,
        title=title,
        severity=severity,
        description=f"Gateway hardening rule for {category} in compound Agent workflows.",
        status="stable",
        conditions=(Condition("content", "regex", pattern, title),),
        condition_logic="any",
        tags={
            "category": category,
            "confidence": "high",
            "source": "atr-agent-security-lab",
        },
    )


HARDENING_RULES = (
    _rule(
        "ATR-GW-1001",
        "Agent credential exfiltration instruction",
        "credential-exfiltration",
        r"(?i)\b(?:send|upload|post|transmit|forward|exfiltrate)\b.{0,100}\b(?:credential|api[ -]?key|access[ -]?token|private[ -]?key|secret)\b.{0,100}\b(?:external|attacker|webhook|paste|email|server)\b",
    ),
    _rule(
        "ATR-GW-1002",
        "Remote-control bootstrap through Agent tool output",
        "remote-control",
        r"(?i)\b(?:curl|wget|download|fetch)\b.{0,120}\b(?:execute|run|source|bash|sh|powershell)\b|\b(?:establish|open|start|connect)\b.{0,50}\b(?:reverse[ -]?shell|remote[ -]?control|command[ -]?and[ -]?control|c2)\b",
    ),
    _rule(
        "ATR-GW-1003",
        "Security policy bypass directive",
        "policy-bypass",
        r"(?i)\b(?:disable|bypass|turn[ -]?off|skip|ignore)\b.{0,100}\b(?:atr|iam|audit|admission|policy|approval|signature[ -]?verification|security[ -]?control)\b",
    ),
    _rule(
        "ATR-GW-1004",
        "Untrusted artifact deployment directive",
        "malicious-deployment",
        r"(?i)\b(?:deploy|release|roll[ -]?out|push)\b.{0,120}\b(?:unsigned|tampered|unverified|unknown[ -]?image|without[ -]attestation|skip[ -]admission)\b",
    ),
    _rule(
        "ATR-GW-1005",
        "Indirect instruction plus high-risk tool action",
        "indirect-prompt-injection",
        r"(?i)\b(?:ignore|disregard|override)\b.{0,80}\b(?:previous|prior|system|developer)\b.{0,120}\b(?:deploy|sign|transfer|send|execute|call[ -]?tool)\b",
    ),
)


def harden_rule_engine(engine: ATREngine) -> tuple[ATREngine, list[dict[str, Any]]]:
    hardened = ATREngine()
    receipts: list[dict[str, Any]] = []
    existing_ids: set[str] = set()
    for rule in engine.rules:
        existing_ids.add(str(rule.id))
        updated = rule
        if rule.id == "ATR-2026-00290" and len(rule.conditions) > 3:
            condition = rule.conditions[3]
            if condition.operator == "regex" and condition.value == BROKEN_DIVERGENCE_PATTERN:
                conditions = list(rule.conditions)
                conditions[3] = replace(condition, value=FIXED_DIVERGENCE_PATTERN)
                updated = replace(rule, conditions=tuple(conditions))
                receipts.append(
                    {
                        "rule_id": rule.id,
                        "condition_index": 3,
                        "action": "replaced_known_invalid_condition",
                        "before_sha256": hashlib.sha256(condition.value.encode()).hexdigest(),
                        "after_sha256": hashlib.sha256(
                            FIXED_DIVERGENCE_PATTERN.encode()
                        ).hexdigest(),
                    }
                )
        hardened.load_rule(updated)
    for rule in HARDENING_RULES:
        if rule.id not in existing_ids:
            hardened.load_rule(rule)
            receipts.append(
                {
                    "rule_id": rule.id,
                    "action": "added_gateway_hardening_rule",
                    "condition_sha256": hashlib.sha256(
                        rule.conditions[0].value.encode()
                    ).hexdigest(),
                }
            )
    return hardened, receipts
