from __future__ import annotations

import base64
import hashlib
import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _pyatr_version() -> str:
    try:
        return version("pyatr")
    except PackageNotFoundError:
        return "unknown"


def add_source_provenance(manifest: dict[str, Any]) -> None:
    manifest["source_provenance"] = {
        "source_path": manifest["source_path"],
        "pyatr_version": _pyatr_version(),
        "gateway_hardening": "v1",
        "rule_checksum": manifest["checksum"],
        "remediation_receipts": manifest["validation_report"].get("remediation_receipts", []),
    }


def _payload(manifest: dict[str, Any]) -> bytes:
    fields = {
        "version": manifest["version"],
        "checksum": manifest["checksum"],
        "source_path": manifest["source_path"],
        "rule_count": manifest["rule_count"],
        "source_provenance": manifest["source_provenance"],
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def sign_bundle_manifest(manifest: dict[str, Any], private_key_path: str) -> None:
    key = serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("ATR bundle signing key must be Ed25519")
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    manifest["signature"] = {
        "algorithm": "Ed25519",
        "public_key_pem": public_pem.decode(),
        "public_key_sha256": hashlib.sha256(public_pem).hexdigest(),
        "value": base64.b64encode(key.sign(_payload(manifest))).decode(),
    }


def verify_bundle_manifest(
    manifest: dict[str, Any],
    *,
    trusted_public_key_path: str = "",
    revoked_key_sha256: list[str] | None = None,
    require_trusted_key: bool = False,
) -> dict[str, str]:
    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        if require_trusted_key:
            raise ValueError("ATR bundle signature is required")
        return {"status": "unsigned", "trust_anchor": "none"}
    bundled_pem = str(signature.get("public_key_pem", "")).encode()
    fingerprint = hashlib.sha256(bundled_pem).hexdigest()
    if fingerprint != signature.get("public_key_sha256"):
        raise ValueError("ATR bundle public key fingerprint mismatch")
    if fingerprint in set(revoked_key_sha256 or []):
        raise ValueError("ATR bundle signing key is revoked")
    if trusted_public_key_path:
        public_pem = Path(trusted_public_key_path).read_bytes()
        trust_anchor = "external"
        if hashlib.sha256(public_pem).hexdigest() != fingerprint:
            raise ValueError("ATR bundle signer does not match trusted public key")
    elif require_trusted_key:
        raise ValueError("ATR bundle requires an external trusted public key")
    else:
        public_pem = bundled_pem
        trust_anchor = "bundled"
    key = serialization.load_pem_public_key(public_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("ATR bundle public key must be Ed25519")
    try:
        key.verify(base64.b64decode(str(signature["value"]), validate=True), _payload(manifest))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("ATR bundle signature verification failed") from exc
    return {"status": "verified", "trust_anchor": trust_anchor, "key_sha256": fingerprint}


def secure_bundle_manifest(manifest: dict[str, Any], settings: Any) -> None:
    add_source_provenance(manifest)
    if settings.atr_bundle_signing_private_key_path:
        sign_bundle_manifest(manifest, settings.atr_bundle_signing_private_key_path)
    manifest["signature_verification"] = verify_bundle_manifest(
        manifest,
        trusted_public_key_path=settings.atr_bundle_trusted_public_key_path,
        revoked_key_sha256=settings.atr_bundle_revoked_key_sha256,
        require_trusted_key=settings.atr_bundle_require_signature,
    )
    manifest["validation_report"]["signature_verification"] = manifest["signature_verification"]
    manifest["validation_report"]["source_provenance"] = manifest["source_provenance"]
