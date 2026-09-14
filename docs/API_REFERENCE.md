# SentinelAI API Reference

Base backend URL (dev): `http://localhost:8000`  
Versioned API prefix: `/api/v1`

---

## 1) System Endpoints

### `GET /api/v1/health`

Liveness probe.

**Response 200**
```json
{
  "status": "ok",
  "service": "SentinelAI",
  "version": "0.1.0",
  "environment": "development",
  "timestamp": "2026-05-02T17:30:00.000Z"
}
```

### `GET /api/v1/ready`

Readiness probe with simulator/orchestrator state.

**Response 200**
```json
{
  "status": "ready",
  "orchestrator_enabled": false,
  "banking_simulator_enabled": true,
  "attack_orchestrator_ready": true,
  "banking_simulator_ready": true,
  "timestamp": "2026-05-02T17:30:01.000Z"
}
```

### `POST /api/v1/demo/reset`

Cancels all active scenarios and clears all banking attacks.

**Response 200**
```json
{
  "cancelled_scenarios": 1,
  "banking_attacks_cleared": true,
  "active_after_reset": []
}
```

---

## 2) Pipeline Endpoint

### `POST /api/v1/pipeline/run`

Runs one full detection pipeline tick and broadcasts same payload to WS clients.

**Query params**
- `attack_type` (optional): one of backend simulator types (e.g., `ddos`, `brute_force`, `sql_injection`)

**Example**
```bash
curl -X POST "http://localhost:8000/api/v1/pipeline/run?attack_type=ddos"
```

**Response 200 (shape)**
```json
{
  "event": {},
  "threat": {},
  "actions": [],
  "response": {},
  "explanation": {}
}
```

---

## 3) Banking Simulator Endpoints

### `POST /api/v1/banking/attack`

Inject a targeted banking attack.

**Query params**
- `attack_type` (required)
- `target_system` (optional)
- `duration_seconds` (optional, >0)

**Example**
```bash
curl -X POST "http://localhost:8000/api/v1/banking/attack?attack_type=sql_injection&target_system=database&duration_seconds=10"
```

**Response 200**
```json
{
  "system": "database",
  "attack_type": "sql_injection",
  "duration_seconds": 10.0,
  "expires_at": "2026-05-02T17:30:12.000Z",
  "peer_system": "transaction_service"
}
```

### `POST /api/v1/banking/clear`

Clear all active banking attacks.

**Response 204** (no body)

### `GET /api/v1/banking/snapshot`

One-shot current simulator frame set without additional event semantics.

**Response 200**
```json
{
  "frames": [
    { "type": "system_update", "system": "api_gateway", "data": {} }
  ]
}
```

---

## 4) Copilot Endpoint

### `POST /api/v1/copilot/chat`

Send prompt to active copilot provider.

**Body**
```json
{
  "prompt": "How should SOC triage this threat?"
}
```

**Response 200**
```json
{
  "answer": "Start by validating source, scope affected assets, and isolate high-risk hosts first."
}
```

**Validation**
- empty/whitespace prompt -> `400`

---

## 5) Attack Orchestrator Endpoints

These routes are mounted at root (not under `/api/v1`).

### `POST /attack`

Schedule scenario in background.

**Body**
```json
{
  "type": "multi_stage"
}
```

Allowed `type` values:
- `ddos`
- `brute_force`
- `sql_injection`
- `insider`
- `multi_stage`

**Response 202**
```json
{
  "type": "multi_stage",
  "run_id": "multi_stage-a1b2c3d4",
  "stages": 11,
  "estimated_duration_seconds": 28.5,
  "started_at": "2026-05-02T17:30:20.000Z",
  "expected_end_at": "2026-05-02T17:30:49.000Z"
}
```

### `GET /attack`

List available scenario types + active runs.

**Response 200**
```json
{
  "available_types": ["ddos", "brute_force", "sql_injection", "insider", "multi_stage"],
  "active": [
    {
      "run_id": "ddos-1a2b3c4d",
      "scenario": "ddos",
      "started_at": "2026-05-02T17:30:20.000Z",
      "expected_end_at": "2026-05-02T17:30:40.000Z"
    }
  ]
}
```

### `DELETE /attack`

Cancel all active scenarios.

**Response 200**
```json
{
  "cancelled": 1
}
```

---

## 6) WebSocket Endpoint

### `WS /ws/live`

Unified real-time stream for pipeline + simulator + scenario + honeypot + side-channel frames.

You can send any text from client to keep connection alive; server ignores content and uses receive loop for disconnect detection.

**Example JS**
```js
const ws = new WebSocket("ws://localhost:8000/ws/live");
ws.onmessage = (e) => {
  const payload = JSON.parse(e.data);
  console.log(payload.type ?? "pipeline", payload);
};
```

---

## 7) WebSocket Frame Types

### 7.1 Pipeline Result (no `type` field)

Contains:
- `event`
- `threat`
- `actions`
- `response`
- `explanation`

### 7.2 `system_update`

```json
{
  "type": "system_update",
  "system": "api_gateway",
  "data": {
    "cpu": 86.3,
    "requests": 9215,
    "latency_ms": 312,
    "error_rate": 2.8,
    "status": "critical",
    "anomalies": ["high_cpu_usage", "traffic_spike"],
    "processes": [],
    "ts": "2026-05-02T17:30:00.000Z"
  }
}
```

### 7.3 `scenario_event`

```json
{
  "type": "scenario_event",
  "scenario": "multi_stage",
  "run_id": "multi_stage-a1b2c3d4",
  "stage": 5,
  "total_stages": 11,
  "severity": "high",
  "system": "database",
  "label": "Lateral movement: SQLi probing /accounts/balance",
  "ts": "2026-05-02T17:30:08.000Z"
}
```

### 7.4 `honeypot_activity`

```json
{
  "type": "honeypot_activity",
  "run_id": "multi_stage-a1b2c3d4",
  "attack_type": "multi_stage",
  "step": 2,
  "total_steps": 6,
  "ts": "2026-05-02T17:30:09.000Z",
  "data": { "action": "credential_dump" }
}
```

### 7.5 `honeypot_analysis`

```json
{
  "type": "honeypot_analysis",
  "run_id": "multi_stage-a1b2c3d4",
  "attack_type": "multi_stage",
  "step": 2,
  "total_steps": 6,
  "ts": "2026-05-02T17:30:09.000Z",
  "data": { "pattern": "credential harvesting", "risk": "high" }
}
```

### 7.6 Side-channel frames

- `anomaly`
- `process_log`
- `recovery`

These are pre-pipeline contextual signals for richer UX.

---

## 7b) Detection, Alerts, Thresholds, Traffic, Reports

All under `/api/v1`.

### Thresholds

| Method | Path | Notes |
|---|---|---|
| `GET` | `/config/thresholds` | Current `Thresholds` object (every tunable in detection / decision / alerting). |
| `PUT` | `/config/thresholds` | Partial JSON patch, e.g. `{"alert_min_risk": 6.0}`. Validated as a whole; `422` on out-of-range. Persists to `THRESHOLDS_PATH` and broadcasts `config_update`. |
| `POST` | `/config/thresholds/reset` | Restore defaults. |

Key fields: `alert_min_risk`, `dedupe_window_s`, `sev_critical/high/medium/low`, `high_risk/low_risk/high_confidence/low_confidence`, `port_scan_min_ports`, `port_scan_seq`, `stuffing_min_users`, `stuffing_fail_ratio`, `lowslow_min_ips`, `lowslow_fail_ratio`, `lowslow_min_gap_s`, `zscore_fire`, `zscore_max`, `baseline_warmup`, `campaign_min_ips`, `campaign_min_subnets`, `campaign_min_fail_ratio`, `if_contamination`, `if_retrain_s`.

### Alerts

| Method | Path | Notes |
|---|---|---|
| `GET` | `/alerts?severity=&status=&type=&entity_type=&limit=` | `{total, items[]}` newest first. |
| `GET` | `/alerts/summary` | Counts by severity / status / type + `raised`, `deduped`, `suppressed`, `suppression_ratio`. |
| `GET` | `/alerts/{id}` | Full `Alert` (risk breakdown, features, z-scores, actions, MITRE, campaign). |
| `PATCH` | `/alerts/{id}` | `{status?, notes?, assignee?}`; status ∈ `new, acknowledged, investigating, resolved, false_positive`. |

### Traffic generator

| Method | Path | Notes |
|---|---|---|
| `POST` | `/traffic/attack` | `{kind, duration_s?, speed?, seed?}` → `202 {id, kind, ...}`. kind ∈ `port_scan, credential_stuffing, low_slow_brute_force, brute_force, ddos, sql_injection`. `speed` divides the campaign's natural cadence (e.g. 30 s → 2 s at `speed=15`). |
| `DELETE` | `/traffic/attack` | Stop all sessions. |
| `GET` | `/traffic/stats` | `events_ingested`, `events_per_sec`, `alerts_*`, `suppression_ratio`, `active_sessions[]`. |
| `PUT` | `/traffic/config` | `{rate_eps?, benign_ratio?, paused?}`. |

### Detection engine

| Method | Path | Notes |
|---|---|---|
| `GET` | `/detection/status` | Forest fit state, population baselines per entity type, active campaigns. |
| `GET` | `/detection/campaigns` | Currently-firing distributed campaigns. |
| `GET` | `/detection/entity/{ip\|user\|subnet}/{key}` | Feature vector, z-scores, baseline, recent events and alerts for one entity. |
| `POST` | `/detection/retrain` | Refit the IsolationForest on the last window of observed vectors. |

### Ingestion

`POST /ingest/replay` — body is NDJSON (one raw log object per line: `source_ip`, `event_type`, `message` or `method/path/status`, optional `username`, `dest_port`, `user_agent`, `status_code`, `endpoint`, `geo`, `asn`). Returns `{ingested, errors}`.

### Reports

`GET /reports/incident?since=<iso>` — JSON summary (`metrics`, `alerts_by_*`, `top_attackers`, `top_targets`, `campaigns`, `mitre_coverage`, `timeline`, `actions`). Send `Accept: text/markdown` for a Markdown rendering.

### New WebSocket frames

- `{"type":"stats","data":{...}}` — once per second, same shape as `/traffic/stats`.
- `{"type":"alert_new","alert":{...}}` / `{"type":"alert_update","alert":{...}}`.
- `{"type":"config_update","thresholds":{...}}`.
- Pipeline frames are unchanged in shape; `threat` gains `risk_breakdown`, `entity`, `features`, `zscores`, `campaign_id`, `mitre`, and the result gains `alert_id`.

## 8) Error Patterns

Common HTTP errors:
- `400`: validation/input mismatch
- `503`: simulator/orchestrator not initialized

For robust clients:
- handle non-200/202 gracefully
- retry websocket with exponential backoff
- ignore malformed frames (frontend validator pattern already implemented)

---

## 9) Suggested Integration Pattern

1. Subscribe to `/ws/live`
2. Keep a unified in-memory event store
3. Split rendering by payload family:
   - pipeline -> dashboard risk/threat/actions/copilot
   - `system_update` -> systems/infrastructure
   - `scenario_event` + `honeypot_*` -> honeypot/report timeline
4. Use `/api/v1/demo/reset` for controlled demo loops

