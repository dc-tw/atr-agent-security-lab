from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.atr_bundle_security import (
    add_source_provenance,
    sign_bundle_manifest,
    verify_bundle_manifest,
)


def _manifest() -> dict[str, object]:
    return {
        "version": "test-v1",
        "checksum": "a" * 64,
        "source_path": "pyatr://default",
        "rule_count": 6,
        "validation_report": {"remediation_receipts": []},
    }


def _keys(tmp_path):  # noqa: ANN001, ANN202
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def test_bundle_signature_uses_external_trust_anchor(tmp_path) -> None:
    private_path, public_path = _keys(tmp_path)
    manifest = _manifest()
    add_source_provenance(manifest)
    sign_bundle_manifest(manifest, str(private_path))
    result = verify_bundle_manifest(
        manifest,
        trusted_public_key_path=str(public_path),
        require_trusted_key=True,
    )
    assert result["status"] == "verified"
    assert result["trust_anchor"] == "external"


def test_bundle_signature_rejects_revoked_key_and_tampering(tmp_path) -> None:
    private_path, public_path = _keys(tmp_path)
    manifest = _manifest()
    add_source_provenance(manifest)
    sign_bundle_manifest(manifest, str(private_path))
    fingerprint = hashlib.sha256(public_path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="revoked"):
        verify_bundle_manifest(manifest, revoked_key_sha256=[fingerprint])

    manifest["rule_count"] = 7
    with pytest.raises(ValueError, match="signature verification"):
        verify_bundle_manifest(manifest, trusted_public_key_path=str(public_path))
