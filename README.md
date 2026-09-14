# SentinelAI — Real-Time Cyber Defense Command Center

SentinelAI is a real-time cyber-defense platform for banking-grade infrastructure. It ingests authentication, network and system telemetry as it happens, scores every event with behavioural machine learning, contains identified threats, and traps adversaries in a live honeypot for forensic analysis — all on a single operations console.

It is built for the hardest case in modern security: **stealthy, distributed attacks that blend into legitimate traffic** — low-and-slow brute force across rotating residential IPs, credential-stuffing from proxy pools, and quiet reconnaissance that static, threshold-based firewalls and SIEMs never catch.

---

## 1) Why SentinelAI

Legacy perimeter firewalls and rule-based SIEMs rely on static thresholds — "flag an IP after 10 failed logins in 60 seconds." Adversaries evade this trivially by throttling attempts across thousands of rotating IPs, and signature-only tools are blind to novel behaviour. The result is the worst of both worlds: **critical low-volume breaches are missed, while analysts drown in tens of thousands of false positives.**

SentinelAI takes a different approach:

- **Behaviour, not thresholds.** Every entity — IP, user, /24 subnet — is scored against its own learned baseline, so an attack that never crosses any fixed count still stands out as anomalous.
- **Explain every alert.** Each detection carries a per-factor risk breakdown, the behavioural deviation that triggered it, the fired detectors, and a MITRE ATT&CK mapping — an analyst can trust and act on it in seconds.
- **Silence the noise.** Legitimate traffic is classified benign and suppressed; a distributed campaign across thousands of IPs collapses into a single alert, not thousands.
- **Get faster over time.** Every confirmed detection is distilled into a signature, so the next occurrence of that adversary is caught instantly, on the first event.

---

## 2) Core Capabilities

### Behavioural detection & risk engine
- Multi-signal fusion: per-entity statistical baselines (online z-scores), an unsupervised **Isolation Forest** for novel/zero-day anomalies, campaign correlation, and dedicated detectors for port scanning, credential stuffing and low-and-slow brute force.
- Dynamic **multi-factor risk score** (0–10) with a transparent per-factor breakdown, mapped to severity and MITRE ATT&CK techniques.
- **Configurable thresholds** tuned live from the console — no redeploy.

### Learned attack signatures
- Confirmed threats are automatically distilled into high-precision signatures keyed on attacker fingerprints (automation-tool user-agents, target endpoints, source subnets for network attacks).
- On a repeat attack the signature fast-path flags the **first event instantly**, before the behavioural window rebuilds. Signatures persist across restarts.

### Banking infrastructure monitoring
- Live host and service telemetry across the banking topology — edge gateway, identity/auth service, transaction engine, fraud scoring, core database, analytics, operations — with CPU, request rate, latency, error rate, process integrity and anomaly state per host.
- Cluster-level health (edge & identity, payments rail, data plane, operations) with lateral-pressure tracking.

### Adversary emulation
- A built-in adversary-emulation engine exercises the defense with realistic, multi-stage attack campaigns — DDoS floods, credential stuffing over residential-proxy pools, low-and-slow brute force, SQL injection, insider abuse and full kill-chains — so detection, response and honeypot behaviour can be validated on demand.
- Campaigns detect **first**, then engage the honeypot — detection leads, containment follows.

### Honeypot & forensic analysis
- Identified adversaries are moved into a decoy mesh; SentinelAI records the full session and streams a live capture alongside a forensic breakdown.
- Behaviour is decomposed into stages, mapped to TTPs (recon, credential theft, lateral movement, exfiltration, persistence) and risk-scored — high-fidelity intelligence you can't get from a blocked connection.

### Alerting & response
- Alert lifecycle (new → acknowledged → investigating → resolved / false-positive) with de-duplication and sub-threshold suppression.
- The decision engine produces priority-ordered response actions — block IP, rate-limit, isolate service, quarantine host, rotate credentials, escalate — each with a human-readable rationale.

### AI copilot & reporting
- Live, plain-language explanation and reasoning for each detection.
- Exportable incident reports — top attackers, targeted accounts, MITRE coverage, full timeline, response actions — as JSON, CSV, Markdown or print/PDF.

---

## 3) The SOC Console

A calm, dense, production-style operations interface (light and dark themes, ⌘K command palette):

| View | Purpose |
|---|---|
| **Overview** | Live posture: throughput, open alerts by severity, suppression, active campaigns, MTTD; risk gauge; alerts-over-time; virtualised live event stream; distributed-campaign strip; AI copilot |
| **Alerts** | Faceted, keyboard-driven triage queue with an **explainability drawer** — risk breakdown, fired signals, behaviour-vs-baseline z-scores, recommended actions, MITRE, notes |
| **Entities** | Per IP / user / subnet / campaign drill-down with feature history and related alerts |
| **Scenarios** | Attack catalog + Detection Lab (launch a vector, watch signals fire and time-to-first-alert live) |
| **Systems / Infrastructure** | Host and topology telemetry across both banking clusters |
| **Honeypot** | Live adversary capture and forensic TTP analysis |
| **Reports** | Incident summary and one-click export |
| **Settings** | Runtime detection thresholds, traffic controls, and the table of learned signatures |

---

## 4) Detection Heuristics

Detection is a **weighted vote across independent signals** — no single rule decides.

**Behavioural features** (11 per entity, over a 300s sliding window, per IP / user / /24):
`fail_ratio, attempts_per_min, distinct_users, distinct_ips, distinct_ports, port_sequentiality, inter_arrival_mean, inter_arrival_std, ua_entropy, hour_of_day_dev, endpoint_diversity`.

**Scorers**

| Scorer | Method | Catches |
|---|---|---|
| Baseline z-score | Welford online mean/variance over the entity population | "this IP/user is unlike a normal one" — even a never-seen address |
| Isolation Forest | scikit-learn, fit on benign traffic, retrained on the live window | novel / zero-day shapes with no rule |
| Campaign clusterer | groups events by client fingerprint; fires on many IPs across many subnets with high failure ratio | residential-proxy-pool credential stuffing |
| Vector detectors | port scan, credential stuffing, low-and-slow — read feature vectors, not message text | the three named evasion vectors |

**Measured performance** (`python -m scripts.eval_detection`, 5,000 events, 85% benign):

| Vector | Precision | Recall | Events to first alert |
|---|---|---|---|
| Port scan | 1.00 | 0.97 | 5 |
| Credential stuffing | 1.00 | 0.94 | 8 |
| Low-and-slow brute force | 1.00 | 0.96 | 5 |
| DDoS | 1.00 | 0.96 | 5 |
| SQL injection | 1.00 | 0.95 | 6 |
| **Benign traffic** | — | — | **0% false-alert rate** |

---

## 5) Architecture

**Backend** (`sentinel-ai-backend`) — Python, FastAPI, asyncio, Pydantic, scikit-learn, numpy.
- `engine/` — features, anomaly scorers, detection, decision, response, signatures.
- `services/` — pipeline orchestration, alert store, traffic/adversary engine, honeypot, banking topology, AI copilot, Kafka ingestor.
- Runtime-configurable thresholds, WS frame schema validation, request-ID middleware, health/readiness probes.

**Frontend** (`sentinel-ai-frontend`) — React, Vite, Tailwind, Recharts, WebSocket streaming; centralized realtime store; lazy-loaded routes; light/dark theming; ⌘K command palette.

**Ingestion** — three paths, one normalized event schema: the live WebSocket pipeline, a **Kafka** consumer (`raw.events`), and an **NDJSON replay** endpoint for batch/forensic re-ingestion. Real syslog / WAF / auth-log sources plug in through the normalizer.

**Ops** — Docker images, Kubernetes manifests, CI with lint, tests and coverage gates (~60 backend tests, ~85% coverage).

---

## 6) Realtime Event Model

SentinelAI streams structured frames over `/ws/live`:

- **Pipeline** — `event`, `threat` (type, risk, confidence, risk breakdown, entity, features, z-scores, MITRE, signature match), `actions`, `response`, `explanation`.
- **Infrastructure** — `system_update`.
- **Scenario** — `scenario_event`.
- **Honeypot** — `honeypot_activity`, `honeypot_analysis`.
- **Operations** — `stats`, `alert_new`, `alert_update`, `config_update`.

All frames are schema-validated before broadcast; the client applies runtime validators before state updates.

---

## 7) API Surface (`/api/v1`)

**System** — `GET /health`, `GET /ready`, `POST /demo/reset`
**Detection & config** — `GET/PUT /config/thresholds`, `POST /config/thresholds/reset`, `GET /detection/status`, `GET /detection/campaigns`, `GET /detection/entity/{type}/{key}`, `POST /detection/retrain`, `GET/DELETE /signatures`
**Alerts** — `GET /alerts`, `GET /alerts/summary`, `GET /alerts/{id}`, `PATCH /alerts/{id}`
**Pipeline & ingestion** — `POST /pipeline/run`, `POST /ingest/replay`
**Adversary emulation** — `POST /traffic/attack`, `DELETE /traffic/attack`, `GET /traffic/stats`, `PUT /traffic/config`, `POST /attack`
**Reports** — `GET /reports/incident` (JSON or `Accept: text/markdown`)

Full details in [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md); architecture in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## 8) Quickstart

```bash
# Backend
cd sentinel-ai-backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend (separate terminal)
cd sentinel-ai-frontend
npm install
npm run dev          # http://localhost:5173
```

Open the console, then drive the defense from the ⌘K command palette or the **Scenarios** view. Tune detection live under **Settings**. Reproduce the detection metrics with:

```bash
cd sentinel-ai-backend
python -m scripts.eval_detection --n 5000 --seed 42
```

Docker / Kubernetes manifests are in `deploy/`; CI is in `.github/workflows/`.

---

## 9) In One Line

**SentinelAI detects the stealthy, distributed attacks that static defenses miss — with real behavioural ML — explains every alert, traps the adversary, and gets faster with every attack it sees.**
