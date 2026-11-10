import json
from types import SimpleNamespace

import httpx
import pytest

from app.core.siem_export import (
    SIEMExporter,
    decrypt_sink_secret,
    encrypt_sink_secret,
)


class ExportRuntime:
    def __init__(self, deliveries):
        self.deliveries = deliveries
        self.completed = []
        self.retried = []

    async def claim_export_deliveries(self, *, limit: int):
        del limit
        result, self.deliveries = self.deliveries, []
        return result

    async def complete_export_delivery(self, delivery_id: str):
        self.completed.append(delivery_id)

    async def retry_export_delivery(self, delivery_id: str, **kwargs):
        self.retried.append((delivery_id, kwargs))


def settings(path: str):
    return SimpleNamespace(
        atr_jsonl_path=path,
        atr_export_encryption_secret="encryption-key",
        atr_export_max_attempts=3,
    )


def test_sink_secret_encryption_round_trip() -> None:
    encrypted = encrypt_sink_secret("webhook-secret", "encryption-key")
    assert encrypted != "webhook-secret"
    assert decrypt_sink_secret(encrypted, "encryption-key") == "webhook-secret"


@pytest.mark.asyncio
async def test_jsonl_delivery_writes_one_record_and_marks_complete(tmp_path) -> None:
    path = tmp_path / "siem.jsonl"
    runtime = ExportRuntime(
        [
            {
                "delivery_id": "delivery-1",
                "sink_type": "jsonl",
                "url": str(path),
                "payload": {"receipt_id": "receipt-1", "action": "block"},
                "attempts": 1,
                "encrypted_secret": "",
            }
        ]
    )
    exporter = SIEMExporter(runtime, settings(str(path)))

    assert await exporter.deliver_once() == 1
    await exporter.close()

    assert runtime.completed == ["delivery-1"]
    assert json.loads(path.read_text()) == {
        "action": "block",
        "receipt_id": "receipt-1",
    }


@pytest.mark.asyncio
async def test_webhook_delivery_is_hmac_signed() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["signature"] = request.headers["x-atr-signature"]
        captured["delivery"] = request.headers["x-atr-delivery"]
        captured["body"] = request.content.decode()
        return httpx.Response(204)

    encrypted = encrypt_sink_secret("signing-secret", "encryption-key")
    runtime = ExportRuntime(
        [
            {
                "delivery_id": "delivery-2",
                "sink_type": "webhook",
                "url": "https://siem.example.test/atr",
                "payload": {"receipt_id": "receipt-2"},
                "attempts": 1,
                "encrypted_secret": encrypted,
            }
        ]
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    exporter = SIEMExporter(runtime, settings("/tmp/unused"), client=client)

    await exporter.deliver_once()
    await client.aclose()

    assert captured["signature"].startswith("sha256=")
    assert captured["delivery"] == "delivery-2"
    assert json.loads(captured["body"]) == {"receipt_id": "receipt-2"}
    assert runtime.completed == ["delivery-2"]
