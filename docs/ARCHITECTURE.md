# SentinelAI Architecture

This document explains SentinelAI end-to-end architecture: runtime components, data flow, real-time messaging, state management, and operational design decisions.

---

## 1) System Overview

SentinelAI is a two-app architecture:

- **Frontend**: React + Vite SOC command center (`sentinel-ai-frontend`)
- **Backend**: FastAPI simulation/detection/orchestration server (`sentinel-ai-backend`)

Both apps communicate over:

- **REST** for command/control and snapshots
- **WebSocket** (`/ws/live`) for live telemetry and incident streams

---

## 2) Backend Architecture

### 2.1 Layered Structure

`app/main.py`
- App factory
- Lifespan startup/shutdown
- Middleware (request-id, latency logging)
- Router registration

`app/api/routes.py`
- Versioned API routes under `/api/v1`
- Health/readiness
- Pipeline trigger
- Banking simulator controls
- Copilot endpoint
- Demo reset endpoint

`app/services/`
- `pipeline.py`: canonical pipeline composition
- `websocket.py`: connection manager + orchestrator
- `banking_simulation.py`: system telemetry simulator
- `attack_orchestrator.py`: scripted scenario runner (`/attack`)
- `honeypot_simulation.py`: honeypot behavior stream
- `anomaly_simulation.py`: side-channel host anomaly stream
- `ai_copilot.py`: mock/A4F provider abstraction

`app/engine/`
- `simulation.py`: synthetic event generation
- `detection.py`: classification/scoring
- `decision.py`: response strategy selection
- `response.py`: simulated response execution report

`app/models/`
- Domain models (`Event`, `Threat`, `Action`)
- WebSocket frame schemas (`ws_frames.py`)

---

## 3) Pipeline Execution Model

Canonical flow (`run_pipeline`):

1. **simulate** event (or accept supplied event)
2. **detect** threat type + confidence + risk score
3. **decide** response actions
4. **respond** execution report
5. **explain** via copilot provider

Output: one `PipelineResult` model (single source of truth payload).

This payload is consumed by dashboard panels (risk meter, threat feed, actions, copilot).

---

## 3b) Detection Heuristics

Detection is a **vote across independent signals**; no single rule decides. Static per-IP thresholds are only one voice.

### Behavioural features (`engine/features.py`)

Every event is indexed into three rolling 300 s windows — by source IP, by username, by /24 subnet — and each view yields an 11-dimensional `FeatureVector`:

`fail_ratio, attempts_per_min, distinct_users, distinct_ips, distinct_ports, port_sequentiality, inter_arrival_mean, inter_arrival_std, ua_entropy, hour_of_day_dev, endpoint_diversity`

### Scorers (`engine/anomaly.py`)

| Scorer | Method | Signal | Catches |
|---|---|---|---|
| `BaselineScorer` | Welford online mean/variance per feature over the *population* of entities of a type; z-score of the current vector | `behavioral_zscore` | "this IP/user looks unlike a typical one" — works for never-seen attacker IPs |
| `IsolationForestScorer` | scikit-learn `IsolationForest` fitted at startup on 2 000 benign vectors, refit on demand from the live window | `isolation_forest` | novel / zero-day shapes with no rule |
| `CampaignClusterer` | groups events by `(user_agent, endpoint)` fingerprint; fires when one fingerprint spans ≥ N IPs across ≥ M subnets **with a high failure ratio** | `distributed_campaign` | residential-proxy-pool credential stuffing where no single IP crosses any threshold |

### Vector detectors (`engine/detection.py`)

Read only the feature vectors, never the message text:

- `port_scan` — `distinct_ports ≥ 10` or sequential-port ratio ≥ 0.7.
- `credential_stuffing` — ≥ 8 distinct usernames with fail ratio ≥ 0.8 from one IP, one /24, **or one campaign fingerprint**.
- `low_slow_brute` — per-*user* view: ≥ 5 distinct IPs targeting one account, fail ratio ≥ 0.8, mean gap ≥ 5 s. Fires with every IP below the legacy per-IP threshold.

### Risk budget

`risk = severity 1.5 + frequency 1.0 + repetition 1.0 + vector 2.0 + behavioral_zscore 2.0 + isolation_forest 1.5 + distributed_campaign 1.0` (clamped to 10). Every `Threat` carries `risk_breakdown` so the UI can show why.

### Alerting

`services/alert_store.py` suppresses threats below `alert_min_risk` and de-duplicates by `(entity, threat_type)` within `dedupe_window_s`, so one campaign yields one alert with a growing `count`. Thresholds live in `core/thresholds.py` and are editable at runtime.

### Evaluation

`python -m scripts.eval_detection` replays 5 000 labelled events; see `docs/JUDGE_PITCH.md` §6b for current numbers.

## 4) Realtime Messaging Design

### 4.1 WebSocket Channel

- Endpoint: `WS /ws/live`
- Broadcast fan-out via connection manager
- Frontend subscribes once and updates centralized realtime store

### 4.2 Event Families

- `PipelineResult` payload (contains `event`, `threat`, `actions`, `response`, `explanation`)
- `system_update`
- `scenario_event`
- `honeypot_activity`
- `honeypot_analysis`
- `anomaly`
- `process_log`
- `recovery`

### 4.3 Contract Safety

Backend:
- All WS frames validated through discriminated schema union in `app/models/ws_frames.py`
- Invalid frame shape fails before broadcast

Frontend:
- Runtime validators in `src/lib/wsValidators.js`
- Malformed payloads are ignored safely

---

## 5) Scenario and Simulation Orchestration

### 5.1 `/attack` Scenario Runner

`POST /attack`:
- schedules multi-stage scenario (background task)
- emits narrative `scenario_event` frames with progressive severity
- injects pressure into banking simulator systems
- launches honeypot sequence in parallel
- broadcasts a pipeline frame so dashboard threat/risk reacts immediately

### 5.2 Banking Simulator

Continuous system-level telemetry:
- CPU, requests, latency, error rate
- status (`normal`, `warning`, `critical`)
- anomalies and process list

Attack injections change metrics over time and can create lateral pressure on peer systems.

---

## 6) Frontend Architecture

> **v2 SOC console.** The frontend was reskinned from the original cinematic
> neon theme to a calm, dense, production-SOC visual system (near-black
> surfaces, one accent, muted semantic severity colours, no glows) and gained
> the screens the ML detection backend enables.

### 6.0 Pages

| Route | Purpose |
|---|---|
| `/` Overview | KPI row (events, ev/s, open alerts by severity, suppression, campaigns, MTTD), risk arc, alerts-over-time chart, virtualised live event stream with real filters, active-campaign strip, AI copilot |
| `/alerts` Alert queue | Dense virtualised table with faceted filters, keyboard triage (`j/k`, `a`ck, `r`esolve, `f`alse-positive), and an **explainability drawer**: per-factor risk breakdown, fired signals, feature-vs-baseline z-score bars, recommended actions, notes |
| `/entities/:type/:key` | Drill-down for an ip / user / subnet / campaign: feature table with z-scores + baseline + sparklines, related alerts, recent events |
| `/scenarios` | Attack catalog + **Detection Lab** tab (launch a vector, watch signals fire and time-to-first-alert live) |
| `/reports` | Incident summary from `/reports/incident`: metrics, alerts by severity/type, MITRE coverage, top attackers/targets, timeline, JSON/CSV/Markdown/Print-PDF export |
| `/settings` | Runtime threshold sliders with live "N of last M events would alert" preview, forest retrain, traffic-generator controls |
| `/systems`, `/infrastructure`, `/honeypot` | Existing simulation views, reskinned |

Realtime store gains `alerts` (id→alert map hydrated from REST on connect and
updated by `alert_new`/`alert_update`), `stats` + `statsHistory` (from the 1 Hz
`stats` frame), `config` (thresholds, from `config_update`), and `eventsMeta`
(threat verdict per event id). New UI primitives: `Table` (+ `useVirtualRows`),
`Drawer`, `Tabs`, `Slider`, `Stat`, `Sparkline`, `Kbd`, `Empty`, plus a ⌘K
`CommandPalette`. The theme is token-driven: legacy `neon-*`/`glass-*` names are
aliased to the calm palette so old panels inherit it without edits.

### 6-legacy) Original Frontend Architecture

### 6.1 UI Layers

- **Layout shell**: sidebar, topbar, route container
- **Pages**:
  - Dashboard
  - Attack Scenarios
  - Systems
  - Infrastructure
  - Honeypot
  - Reports
- **Panels/components**: focused visual modules (risk, feed, terminal, timeline, analysis)

### 6.2 Realtime State Model

`useRealtimeEvents` builds a single state object:
- `events`
- `currentThreat`
- `riskScore`
- `actions`
- `explanation`
- `telemetryLogs`
- `scenarioEvents`
- `systemUpdates`
- `honeypotActivities`
- `honeypotAnalyses`

Deduplication keys prevent noisy repeated renders for scenario/honeypot streams.

### 6.3 Performance Strategy

- Route-level lazy loading for heavy pages
- Sidebar hover/focus prefetch for likely next navigation
- Lightweight dashboard first paint

---

## 7) Operational Reliability Features

- `GET /api/v1/health` for liveness
- `GET /api/v1/ready` for readiness checks
- `POST /api/v1/demo/reset` to cancel/clear active simulation state
- Request correlation middleware:
  - incoming/generated `x-request-id`
  - latency logging per request

---

## 8) Quality Gates

Frontend:
- ESLint
- Vitest tests + coverage thresholds
- production build check

Backend:
- compile checks
- pytest suites
- coverage threshold via `pytest-cov`

CI workflow enforces both tracks on push/PR.

---

## 9) Design Trade-offs

Why this architecture works for demo + extension:

- **Pros**
  - clear separation of concerns
  - real-time first user experience
  - deterministic API contract boundaries
  - easy feature verticals (new scenario, new panel, new simulator)

- **Trade-offs**
  - in-memory runtime state (no persistence layer yet)
  - simulation-heavy by design (not wired to real SOC telemetry feeds yet)
  - single-node assumptions for websocket manager

---

## 10) Extension Points

- Plug real data ingestion into `run_pipeline(event=...)`
- Add persistence and replay APIs
- Add auth/RBAC at API and route layer
- Add external alert/incident integrations
- Extend event schemas and typed generation for all 50 vectors

