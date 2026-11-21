from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _private_key() -> tuple[Ed25519PrivateKey, str]:
    configured = os.getenv("ATR_LAB_EVIDENCE_PRIVATE_KEY", "").strip()
    if configured:
        key = serialization.load_pem_private_key(Path(configured).read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("ATR_LAB_EVIDENCE_PRIVATE_KEY must contain an Ed25519 private key")
        return key, "configured-ed25519-key"
    return Ed25519PrivateKey.generate(), "ephemeral-lab-key"


def create_evidence_bundle(
    output: Path,
    manifest: dict[str, Any],
    report: str,
) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.zh-TW.md"
    report_path.write_text(report)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "atr-agent-security-lab"}},
        "components": [
            {
                "type": "container",
                "name": service,
                "version": image,
                "hashes": [{"alg": "SHA-256", "content": image.removeprefix("sha256:")}],
            }
            for service, image in sorted(manifest.get("image_ids", {}).items())
        ],
    }
    sbom_path = output / "sbom.cdx.json"
    sbom_path.write_text(json.dumps(sbom, ensure_ascii=False, indent=2) + "\n")

    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": "atr-agent-security-lab", "digest": {"gitCommit": manifest["git_sha"]}}
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/dc-tw/atr-agent-security-lab/compound-lab/v0.6",
                "externalParameters": {
                    "model": manifest.get("model"),
                    "policyVersion": manifest.get("policy_version"),
                    "bundleChecksum": manifest.get("bundle_checksum"),
                },
                "resolvedDependencies": [
                    {
                        "uri": f"docker://{service}",
                        "digest": {"sha256": image.removeprefix("sha256:")},
                    }
                    for service, image in sorted(manifest.get("image_ids", {}).items())
                ],
            },
            "runDetails": {"builder": {"id": "atr-lab-local-evidence-builder"}},
        },
    }
    provenance_path = output / "provenance.intoto.json"
    provenance_path.write_text(json.dumps(provenance, ensure_ascii=False, indent=2) + "\n")

    manifest["evidence_files"] = {
        path.name: {"sha256": _sha256(path), "bytes": path.stat().st_size}
        for path in (report_path, sbom_path, provenance_path)
    }
    private_key, identity = _private_key()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    manifest["evidence_signer"] = {
        "algorithm": "Ed25519",
        "identity": identity,
        "public_key_sha256": hashlib.sha256(public_pem).hexdigest(),
    }
    manifest_path = output / "manifest.json"
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
    manifest_path.write_bytes(manifest_bytes)
    (output / "manifest.sig").write_text(
        base64.b64encode(private_key.sign(manifest_bytes)).decode() + "\n"
    )
    (output / "evidence-public-key.pem").write_bytes(public_pem)
    return manifest


def verify_evidence_bundle(
    output: Path,
    *,
    trusted_public_key: Path | None = None,
    expected_key_sha256: str | None = None,
) -> dict[str, Any]:
    manifest_path = output / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    bundled_public_pem = (output / "evidence-public-key.pem").read_bytes()
    expected_key = manifest["evidence_signer"]["public_key_sha256"]
    if hashlib.sha256(bundled_public_pem).hexdigest() != expected_key:
        raise ValueError("evidence public key fingerprint mismatch")
    public_pem = (
        trusted_public_key.read_bytes() if trusted_public_key is not None else bundled_public_pem
    )
    actual_key_sha256 = hashlib.sha256(public_pem).hexdigest()
    if actual_key_sha256 != expected_key:
        raise ValueError("trusted public key does not match evidence signer")
    if expected_key_sha256 is not None and actual_key_sha256 != expected_key_sha256.lower():
        raise ValueError("evidence signer does not match expected key fingerprint")
    key = serialization.load_pem_public_key(public_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("evidence public key is not Ed25519")
    try:
        signature = base64.b64decode((output / "manifest.sig").read_text().strip(), validate=True)
        key.verify(signature, manifest_bytes)
    except (binascii.Error, InvalidSignature) as exc:
        raise ValueError("evidence manifest signature verification failed") from exc
    for name, record in manifest["evidence_files"].items():
        path = output / name
        if _sha256(path) != record["sha256"] or path.stat().st_size != record["bytes"]:
            raise ValueError(f"evidence file verification failed: {name}")
    return {
        "valid": True,
        "run_id": manifest["run_id"],
        "signer": manifest["evidence_signer"],
        "trust_anchor": "external" if trusted_public_key or expected_key_sha256 else "bundled",
        "verified_files": sorted(manifest["evidence_files"]),
    }
