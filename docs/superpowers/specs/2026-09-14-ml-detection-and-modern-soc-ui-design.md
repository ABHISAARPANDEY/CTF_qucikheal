# SentinelAI — ML Detection Layer & Modern SOC UI

**Date:** 2026-09-14
**Status:** Approved
**Problem statement:** Tier-1 neo-bank SOC; detect low-and-slow distributed brute force, credential stuffing (residential proxy pools) and port scans that evade static-threshold SIEMs; multi-factor risk scoring with configurable thresholds; live SOC dashboard with severity filters; exportable IR reports.

## Assessment of current state (score 5.5/10)

Strengths: async FastAPI streaming, multi-signal rules engine (`engine/detection.py`), tiered decision playbook, WS frame validation, ops discipline (CI, Docker, k8s, readiness), polished UI, honeypot/banking simulators.

Gaps vs. brief: no statistical/ML detection; only 3 attack generators (no port scan, no credential stuffing, no benign traffic); events pre-labelled so detection ≈ keyword match; thresholds hard-coded; no Alert lifecycle; severity filter not wired; reports are raw dumps; UI is neon-cyberpunk rather than a production SOC tool.

## Goals

1. Detect the three named vectors with behavioural + unsupervised methods, not static per-IP thresholds.
2. Multi-factor risk score with per-factor breakdown and runtime-configurable thresholds.
3. Alert model with lifecycle + dedupe (alert-fatigue answer).
4. Calm, dense, modern SOC UI: alert queue, explainability drawer, entity drill-down, settings, reports.
5. Measurable: eval script prints precision/recall per attack type.

## Non-goals

Real Kafka cluster, persistence beyond process memory (except thresholds.json), auth/RBAC, PDF generation library (browser print instead), light theme.

---

## 1. Backend — ingestion & simulation

### 1.1 Event model (`app/models/event.py`) — additive optional fields
`username: str|None`, `dest_port: int|None`, `user_agent: str|None`, `status_code: int|None`, `endpoint: str|None`, `geo: str|None` (ISO country), `asn: int|None`, `label: str|None` (ground-truth attack type for eval only; never used by detection).

### 1.2 Generators (`app/engine/simulation.py`) — registered in `SIMULATORS`
| key | shape |
|---|---|
| `benign` | logins 200, API calls, health checks. Realistic UA pool, business-hours weighted. Severity INFO. |
| `port_scan` | one IP, distinct `dest_port` per event, sequential or random; message `"SYN <src>:<sport> -> <dst>:<dport> flags=S"`. No "scan" keyword. |
| `credential_stuffing` | many distinct usernames, 1 attempt each, 401s, from a `/24` pool sharing one UA; endpoint `/oauth/token` or `/api/login`. |
| `low_slow_brute_force` | one target username, each attempt from a fresh IP, 401, spacing 20–60s (compressed for demo via a `speed` factor). |
| `ddos`, `brute_force`, `sql_injection` | kept; messages de-labelled where feasible (keep keywords for backward compat of lexical signal). |

Generators are *stateful sessions*: `AttackSession(kind).next() -> Event` so multi-event campaigns keep the same IP / user / UA across events. `generate_event()` remains for single-shot use.

### 1.3 Traffic generator (`app/services/traffic_generator.py`)
Background asyncio task, on by default (`traffic_enabled=True`, `traffic_rate_eps=20`, `traffic_benign_ratio=0.9`). Each tick emits a mix of benign events and events from active `AttackSession`s, runs `run_pipeline(event=...)`, broadcasts the pipeline frame, feeds the AlertStore. Maintains `Stats{events_ingested, events_per_sec (1s EWMA), alerts_raised, alerts_deduped, suppression_ratio, started_at}`; broadcasts a `stats` frame every 1s. `POST /api/v1/traffic/attack {kind, duration_s, speed}` starts a session; the attack orchestrator's scenarios call this for their event bursts. `GET /api/v1/traffic/stats`.

### 1.4 Replay
`POST /api/v1/ingest/replay` — NDJSON body; each line → `normalize_to_event` → pipeline. Returns counts.

---

## 2. Backend — detection & risk

### 2.1 FeatureStore (`app/engine/features.py`)
Bounded, lock-protected rolling windows (300s, cap 200 per bucket) keyed by `ip`, `user`, `subnet` (`/24`). `FeatureStore.observe(event) -> dict[EntityType, FeatureVector]`.

`FeatureVector` (dataclass, all floats):
`fail_ratio, attempts_per_min, distinct_users, distinct_ips, distinct_ports, port_sequentiality, inter_arrival_mean, inter_arrival_std, ua_entropy, hour_of_day_dev, endpoint_diversity`. `.as_array()` for sklearn.

### 2.2 Anomaly scorers (`app/engine/anomaly.py`)
- `BaselineScorer` — Welford/EWMA per (entity, feature). `score(entity, fv) -> Signal("behavioral_zscore", fired=z>=2, strength=clip(z/4))`. Warm-up: ≥ 10 samples. Also returns per-feature z-scores for the UI.
- `IsolationForestScorer` — `sklearn.ensemble.IsolationForest(n_estimators=100, contamination=0.05, random_state=42)`. Fit at startup on 2000 benign vectors from the generator; `refit(window)` every `if_retrain_seconds=300` in a thread. `score(fv) -> Signal("isolation_forest", strength = clip((offset - score_samples)/scale))`.
- `CampaignClusterer` — fingerprint `(user_agent, endpoint, username-or-None)`; keeps recent members. If ≥ `campaign_min_ips` distinct IPs across ≥ `campaign_min_subnets` subnets within window → `Signal("distributed_campaign")` + `campaign_id` (uuid5 of fingerprint).

### 2.3 Dedicated vector signals (in `detection.py`, using FeatureVector)
- `port_scan`: `distinct_ports >= T.port_scan_min_ports` or `port_sequentiality >= T.port_scan_seq`.
- `credential_stuffing`: ip/subnet view `distinct_users >= T.stuffing_min_users and fail_ratio >= T.stuffing_fail_ratio`.
- `low_slow_brute`: user view `distinct_ips >= T.lowslow_min_ips and fail_ratio >= T.lowslow_fail_ratio and inter_arrival_mean >= T.lowslow_min_gap_s`.

Candidate scoring adds `ThreatType.CREDENTIAL_STUFFING`; `PORT_SCAN`/`BRUTE_FORCE` gain their vector signals so they fire without lexical match.

### 2.4 Risk & Threat
`calculate_risk` budget: severity 2.0 · frequency 1.5 · repetition 1.5 · behavioral_zscore 2.0 · isolation_forest 1.5 · distributed_campaign 1.5 → clamp [0,10]. Returns `(risk, breakdown: dict[str,float])`.

`Threat` gains: `risk_breakdown`, `entity: {type, key}`, `features: FeatureVector`, `zscores: dict[str,float]`, `campaign_id`, `mitre: list[str]` (map: brute→T1110.001, stuffing→T1110.004, port_scan→T1046, ddos→T1498, sqli→T1190, low_slow→T1110.001+T1078).

### 2.5 Thresholds (`app/core/thresholds.py`)
Pydantic `Thresholds` model with every tunable above plus `alert_min_risk=4.0`, severity cut points, `dedupe_window_s=60`. Singleton with `get()/set()`; `PUT` validates, writes `thresholds.json`, broadcasts `config_update` frame. Routes `GET/PUT /api/v1/config/thresholds`, `POST /api/v1/config/thresholds/reset`.

### 2.6 Alerts (`app/models/alert.py`, `app/services/alert_store.py`)
`Alert{id, threat_id, threat_type, entity, severity, risk, count, first_seen, last_seen, status: new|acknowledged|investigating|resolved|false_positive, assignee, notes, actions, mitre, campaign_id}`.
`AlertStore` ring (cap 1000). `ingest(threat, actions)`: if `risk < alert_min_risk` → suppressed (counted). Else dedupe key `(entity.key, threat_type)` within `dedupe_window_s` → increment `count`, bump `risk=max`, `last_seen`; broadcast `alert_update`; otherwise create → `alert_new`.
Routes: `GET /alerts?severity&status&type&entity_type&limit`, `GET /alerts/{id}`, `PATCH /alerts/{id} {status, notes, assignee}`, `GET /alerts/summary` (counts by severity/status/type).

### 2.7 Reports
`GET /api/v1/reports/incident?since=<iso>` → `{generated_at, window, metrics{events_ingested, alerts_raised, suppressed, suppression_ratio, mttd_s}, alerts_by_severity, alerts_by_type, top_attackers[{ip, alerts, risk_max}], top_targets[{user, alerts}], campaigns[], mitre_coverage[{technique, count}], timeline[], actions[]}`. `Accept: text/markdown` renders the same as Markdown.

### 2.8 Eval
`scripts/eval_detection.py`: seeds RNG, runs 5000 mixed events (benign 85%, rest across vectors) through the pipeline with `label` ground truth, prints precision/recall/F1 per type and mean time-to-first-alert per campaign.

### 2.9 WS frames (additive)
`stats`, `alert_new`, `alert_update`, `config_update`. Pipeline frame unchanged in shape (additive fields on `threat`). All added to `ws_frames.py` validators.

---

## 3. Frontend — visual system

`index.css @theme`: surfaces `--bg-0 #0a0a0b`, `--bg-1 #111113`, `--bg-2 #18181b`, `--bg-3 #1f1f23`; borders `white/6%`, `white/12%`; text `#fafafa / #a1a1aa / #71717a / #52525b`; accent `#6366f1` (hover `#818cf8`); severity critical `#ef4444`, high `#f97316`, medium `#eab308`, low `#22c55e`, info `#71717a`. Remove: `AmbientBackground`, glow utilities, scanline/marquee/heartbeat keyframes. Motion: 150ms mount fade/translate; list insert 200ms; `prefers-reduced-motion` disables.

Shell: 56px icon rail (`Sidebar`), expands to 220px on hover; nav groups **Detect** (Overview, Alerts, Entities via search), **Simulate** (Scenarios, Systems, Infrastructure, Honeypot), **Operate** (Reports, Settings). Topbar: stats strip (`ev/s · open alerts by sev · suppression % · WS status`), ⌘K palette (`components/CommandPalette.jsx`: pages, launch scenario, ack alert by id, quick threshold), mode toggle + demo reset kept.

UI primitives added under `components/ui/`: `table` (dense, sticky header, `useVirtualRows` hook), `drawer`, `tabs`, `slider`, `kbd`, `sparkline`, `stat`. Charts: Recharts, muted palette, no gradients/glows.

## 4. Frontend — pages

- `/` Overview: KPI `stat` row; risk arc; alerts-over-time stacked area (5-min buckets); live event stream (virtualised 500, filters: severity multi-select, type, text; filters actually filter); active campaigns strip.
- `/alerts` Alert Queue: dense table (sev · type · entity · risk · count · age · status · MITRE), facets, sort, keyboard (`j/k`, `a` ack, `r` resolve, `enter` open). Explain drawer: risk breakdown bars, fired signals, feature-vs-baseline z-score diverging bars, IF score, campaign members, recommended actions (from threat.actions), status buttons, notes.
- `/entities/:type/:key`: header, per-feature sparklines (from entity history in store), events, alerts, campaign link.
- `/scenarios`: restyled catalog; new generators added with "expected detector" tag; **Detection Lab** tab: launch → scoreboard (signals fired, time-to-alert, risk trajectory).
- `/systems`, `/infrastructure`, `/honeypot`: restyle only.
- `/reports`: renders `/reports/incident`; export JSON/CSV/Markdown; print stylesheet + "Print / Save PDF".
- `/settings`: threshold sliders bound to `/config/thresholds`; live preview "N of last 500 events would alert"; traffic rate; retrain interval; reset.

State: store slices `alerts` (map + order), `config`, `stats`, `campaigns`, `entityHistory` (ring per entity key, cap 200). Validators for new frames. Selectors memoised.

## 5. Testing

Backend (pytest): features windowing; each scorer deterministic; each vector signal fires on its generator and not on benign; risk breakdown sums; AlertStore dedupe + suppression; thresholds PUT hot-swap + persistence; report endpoint shape; eval script smoke. Frontend (vitest): new validators, alert filter/sort, threshold preview, command palette actions.

## 6. Delivery

README + `docs/ARCHITECTURE.md` + `docs/API_REFERENCE.md` updated (ML heuristics section, threshold config, new endpoints, eval numbers). `requirements.txt`: `numpy`, `scikit-learn`.
