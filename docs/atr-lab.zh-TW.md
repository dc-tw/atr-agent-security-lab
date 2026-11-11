# ATR Agent Security Lab 操作與驗收

## 版本定位

`atr-governance` 是長期研究分支，版本為 `v0.2.0-atr-lab`。本版只承諾本機 Docker Lab；
Goals、ACP、Skill、forecast、presence、Chief／Worker、多 Agent、Workflow YAML、Kubernetes、
正式 OIDC、TLS、multi-AZ 與 production SLA 不在驗收範圍。

## 一個指令啟動與驗證

```bash
./scripts/atr_lab_up.sh
./scripts/test_atr_lab.sh
```

驗收腳本預設使用 `python3`；若專案環境使用其他直譯器，可指定
`PYTHON_BIN=.venv/bin/python ./scripts/test_atr_lab.sh`。

管理 API 使用 `X-API-Key: atr-lab-admin`。Dashboard 位於 `http://127.0.0.1:3000`，Gateway 位於
`http://127.0.0.1:8000`。停止環境：

```bash
docker compose -f docker-compose.atr-lab.yml down
```

若要清除 PostgreSQL、Redis、Ollama 與 simulator 資料，需由操作者明確執行 `down --volumes`；
一般驗收不會自動刪除資料。

## Agent、工具與 ATR 邊界

Agent 只看得到兩個 server-side allow-list 工具：

- `read_untrusted_page(fixture_id)`：只接受 `benign` 或 `indirect-injection`。
- `deploy_release(environment, version, change)`：固定呼叫內部 simulator，必須依序完成 ATR
  exception approval 與 tool side-effect approval。Gateway 自行建立 idempotency key，模型不能指定 endpoint。

| Boundary | 合法動作 |
|---|---|
| `request_input` | `detect`, `block` |
| `planner_output` | `detect`, `block` |
| `tool_call` | `detect`, `block`, `require_approval` |
| `tool_response` | `detect`, `block`, `quarantine` |
| `model_output` | `detect`, `block` |

Blocking policy 會緩衝完整 model output，掃描通過後才送出 `draft_token`。Detection-only 可以先串流，
其 finding 的 `released_before_scan` 會標記為 `true`。Quarantine 只保存 placeholder 與 finding IDs，
不把工具原文送進下一輪模型 context。

## 核准、crash/resume 與失效規則

ATR approval 與工具副作用 approval 是兩筆不同決策。ATR approval 綁定 tenant、run、boundary、
finding／rule、content fingerprint、policy version 與 bundle checksum；policy 或 bundle 更新後，舊核准會
收到 `409`。核准 ATR 不跳過治理，並新增 `approved_exception` enforcement receipt。

Deployment simulator 以 SQLite 獨立持久化並依 idempotency key 去重。驗收會在第二階段核准前 SIGKILL
Gateway，再啟動並恢復；通過條件是核准前零副作用、恢復後只執行一次。

## Rule health

Loader 逐一驗證 regex condition。無效規則在 detection-only 以 degraded health 啟動並停用；blocking
policy 只有在所有 invalid rule IDs 被修復、替換或明確列入 `excluded_rule_ids` 後才能啟用。
`ATR-2026-00290` 的已知無效 condition 會列入 manifest 的 `invalid_conditions` 與 activation record，
不再只有 console warning。規則驗收依 checksum、有效／無效數量及 health，不硬編碼規則總數。

## 證據與隱私

每次驗收會輸出：

- `artifacts/atr-lab/<run-id>/manifest.json`
- `artifacts/atr-lab/<run-id>/report.zh-TW.md`

內容包含 Git SHA、container image ID、模型、pyatr 版本、bundle checksum、policy version、rule health、
scenario 結果與 latency。只保存 case ID、fingerprint 與聚合結果，不保存原始 prompt、tool response 或命中片段。
驗收會搜尋 live SSE、Redis dump 與 PostgreSQL events／audit／run／conversation／finding，確保 synthetic
canary 未被保存。

## Ollama exploratory gate

```bash
docker compose -f docker-compose.atr-lab.yml --profile ollama up -d --build --wait
python scripts/verify_atr_lab_ollama.py
```

模型固定為 `qwen2.5:0.5b-instruct`。通過標準是 benign tool flow 及 indirect-injection quarantine 的
Gateway 控制路徑正確，不要求模型產生固定文字，也不把「模型是否必然受騙」當成 ATR 成效標準。
