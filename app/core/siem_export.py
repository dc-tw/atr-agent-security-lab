from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import httpx
from cryptography.fernet import Fernet


def _fernet(secret: str) -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def encrypt_sink_secret(secret: str, encryption_secret: str) -> str:
    return _fernet(encryption_secret).encrypt(secret.encode()).decode()


def decrypt_sink_secret(secret: str, encryption_secret: str) -> str:
    if not secret:
        return ""
    return _fernet(encryption_secret).decrypt(secret.encode()).decode()


class SIEMExporter:
    def __init__(
        self, runtime: Any, settings: Any, *, client: httpx.AsyncClient | None = None
    ) -> None:
        self.runtime = runtime
        self.settings = settings
        self._client = client or httpx.AsyncClient(timeout=15.0, follow_redirects=False)
        self._owns_client = client is None

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def deliver_once(self) -> int:
        deliveries = await self.runtime.claim_export_deliveries(limit=20)
        for delivery in deliveries:
            try:
                await self._deliver(delivery)
                await self.runtime.complete_export_delivery(delivery["delivery_id"])
            except Exception as exc:
                attempts = int(delivery["attempts"])
                terminal = attempts >= self.settings.atr_export_max_attempts
                await self.runtime.retry_export_delivery(
                    delivery["delivery_id"],
                    error=f"{type(exc).__name__}: {exc}",
                    retry_seconds=min(3_600, 2 ** min(attempts, 11)),
                    terminal=terminal,
                )
        return len(deliveries)

    async def _deliver(self, delivery: dict[str, Any]) -> None:
        payload = json.dumps(
            delivery["payload"], ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        sink_type = delivery["sink_type"]
        if sink_type == "jsonl":
            path = Path(delivery["url"])
            configured = Path(self.settings.atr_jsonl_path)
            if path != configured:
                raise ValueError("JSONL sink path does not match the configured path")
            await asyncio.to_thread(self._append_jsonl, path, payload)
            return
        if sink_type == "webhook":
            secret = decrypt_sink_secret(
                delivery["encrypted_secret"],
                self.settings.atr_export_encryption_secret,
            )
            signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
            response = await self._client.post(
                delivery["url"],
                content=payload.encode(),
                headers={
                    "Content-Type": "application/json",
                    "X-ATR-Signature": f"sha256={signature}",
                    "X-ATR-Delivery": str(delivery["delivery_id"]),
                },
            )
            response.raise_for_status()
            return
        raise ValueError(f"Unsupported SIEM sink type: {sink_type}")

    @staticmethod
    def _append_jsonl(path: Path, payload: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(payload + "\n")


async def run_siem_exporter(exporter: SIEMExporter, poll_seconds: float) -> None:
    while True:
        try:
            delivered = await exporter.deliver_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            delivered = 0
        if not delivered:
            await asyncio.sleep(poll_seconds)
