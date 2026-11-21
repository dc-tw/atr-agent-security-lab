from __future__ import annotations

import json

import pytest

from scripts.evidence_bundle import create_evidence_bundle, verify_evidence_bundle


def _manifest() -> dict[str, object]:
    return {
        "schema_version": "v0.5.0-atr-rule-hardening",
        "run_id": "evidence-test",
        "git_sha": "a" * 40,
        "model": "mock",
        "policy_version": "policy-v1",
        "bundle_checksum": "b" * 64,
        "image_ids": {"gateway": "sha256:" + "c" * 64},
    }


def test_signed_evidence_bundle_verifies_offline(tmp_path) -> None:
    create_evidence_bundle(tmp_path, _manifest(), "# 測試報告\n")
    result = verify_evidence_bundle(tmp_path)
    assert result["valid"] is True
    assert result["verified_files"] == [
        "provenance.intoto.json",
        "report.zh-TW.md",
        "sbom.cdx.json",
    ]
    assert json.loads((tmp_path / "sbom.cdx.json").read_text())["bomFormat"] == "CycloneDX"


def test_tampered_evidence_bundle_is_rejected(tmp_path) -> None:
    create_evidence_bundle(tmp_path, _manifest(), "# original\n")
    (tmp_path / "report.zh-TW.md").write_text("# tampered\n")
    with pytest.raises(ValueError, match="verification failed"):
        verify_evidence_bundle(tmp_path)


def test_tampered_manifest_signature_is_rejected_cleanly(tmp_path) -> None:
    create_evidence_bundle(tmp_path, _manifest(), "# original\n")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(manifest.read_text().replace("evidence-test", "evidence-evil"))
    with pytest.raises(ValueError, match="manifest signature"):
        verify_evidence_bundle(tmp_path)


def test_evidence_bundle_can_require_external_trust_anchor(tmp_path) -> None:
    create_evidence_bundle(tmp_path, _manifest(), "# Report\n")
    trusted_key = tmp_path / "trusted.pem"
    trusted_key.write_bytes((tmp_path / "evidence-public-key.pem").read_bytes())
    fingerprint = json.loads((tmp_path / "manifest.json").read_text())["evidence_signer"][
        "public_key_sha256"
    ]
    result = verify_evidence_bundle(
        tmp_path,
        trusted_public_key=trusted_key,
        expected_key_sha256=fingerprint,
    )
    assert result["trust_anchor"] == "external"
    with pytest.raises(ValueError, match="expected key fingerprint"):
        verify_evidence_bundle(tmp_path, expected_key_sha256="0" * 64)
