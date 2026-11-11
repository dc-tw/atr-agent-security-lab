#!/bin/sh
set -eu
PYTHON_BIN="${PYTHON_BIN:-python3}"
"${PYTHON_BIN}" -m ruff check app tests scripts
"${PYTHON_BIN}" -m pytest -q
"${PYTHON_BIN}" scripts/evaluate_atr_corpus.py
"${PYTHON_BIN}" scripts/benchmark_atr.py --iterations 200 --max-p95-ms 50
docker compose -f docker-compose.atr-lab.yml config --quiet
docker compose -f docker-compose.atr-lab.yml up -d --build --wait
"${PYTHON_BIN}" scripts/verify_atr_lab.py
