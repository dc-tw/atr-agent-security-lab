#!/bin/sh
set -eu
docker compose -f docker-compose.atr-lab.yml up -d --build --wait
printf '%s\n' 'ATR Lab ready: API http://127.0.0.1:8000, Dashboard http://127.0.0.1:3000'
