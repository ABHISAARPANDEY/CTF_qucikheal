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

