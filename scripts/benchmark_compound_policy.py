from __future__ import annotations

# ruff: noqa: E501 -- keep the benchmark output line machine-readable.
import argparse
import statistics
import time

from app.lab_services.compound_policy import (
    evaluate_atr,
    evaluate_deployment,
    evaluate_iam,
    evaluate_signing,
    evaluate_supply_chain,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--max-p95-ms", type=float, default=100.0)
    args = parser.parse_args()
    samples: list[float] = []
    for _ in range(args.iterations):
        started = time.perf_counter()
        evaluate_atr(synthetic_threat=False)
        evaluate_iam(
            subject="engineer-a",
            device="device-A",
            target="wallet",
            token_claims={
                "subject": "engineer-a",
                "device": "device-A",
                "audience": "deployment",
                "scope": "wallet",
                "artifact_digest": "sha256:wallet-v1",
                "valid": True,
            },
            artifact_digest="sha256:wallet-v1",
        )
        evaluate_supply_chain(artifact_id="wallet-v1-signed", image_digest="sha256:wallet-v1")
        evaluate_deployment(artifact_id="wallet-v1-signed", environment="production")
        evaluate_signing(
            operation="transfer",
            amount_atomic="1000",
            destination="treasury-cold",
            intent_id="intent",
            workload_attested=True,
        )
        samples.append((time.perf_counter() - started) * 1000)
    p95 = statistics.quantiles(samples, n=100, method="inclusive")[94]
    print(
        f"compound_policy_iterations={args.iterations} p95_ms={p95:.3f} gate_ms={args.max_p95_ms:.3f}"
    )
    return 0 if p95 < args.max_p95_ms else 1


if __name__ == "__main__":
    raise SystemExit(main())
