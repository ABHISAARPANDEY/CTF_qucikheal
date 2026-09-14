# Frontend Modern SOC UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the neon-cyberpunk theme with a calm, dense, production-SOC visual system and add the screens the new backend enables: alert queue with explainability drawer, entity drill-down, detection lab, threshold settings, and a real incident report.

**Architecture:** Theme migration is done through token aliasing in `index.css` — legacy token names (`neon-*`, `glass-*`, `bg-elevated`, …) are redefined to the calm palette and glow utilities become no-ops, so the 31 legacy components restyle without edits. New screens use new semantic tokens and a small set of new primitives (`Table`, `Drawer`, `Tabs`, `Slider`, `Stat`, `Sparkline`, `Kbd`, `CommandPalette`). The realtime store gains `alerts`, `stats`, `config` slices fed by the new WS frames and hydrated from REST on connect.

**Tech Stack:** React 19, Vite 8, Tailwind v4 (`@theme`), framer-motion (mount transitions only), lucide-react, Recharts 3, react-router 7, vitest. All commands run from `sentinel-ai-frontend/`.

---

## File map

| File | Responsibility |
|---|---|
| `src/index.css` (rewrite) | new tokens + legacy aliases, glow neutralisation, base styles, print stylesheet |
| `src/lib/api.js` (extend) | thresholds, alerts, traffic, detection, reports clients |
| `src/lib/wsValidators.js` (extend) | `isValidAlertFrame`, `isValidStatsFrame`, `isValidConfigFrame` |
| `src/lib/useRealtimeEvents.js` (extend) | `alerts`, `stats`, `config` slices; hydrate alerts on open; events cap 500 |
| `src/lib/RealtimeProvider.jsx`, `src/lib/selectors.js` (extend) | pass-through + selectors (`selectAlerts`, `selectAlertList`, `selectStats`, `selectConfig`) |
| `src/lib/format.js` (new) | `fmtTime`, `fmtAgo`, `fmtNum`, `severityRank`, `SEVERITY_ORDER` |
| `src/components/ui/{table,drawer,tabs,slider,stat,sparkline,kbd,empty}.jsx` (new) | primitives |
| `src/components/CommandPalette.jsx` (new) | ⌘K |
| `src/components/Sidebar.jsx`, `Topbar.jsx` (rewrite) | icon rail + stats strip |
| `src/components/overview/OverviewPage.jsx`, `KpiRow.jsx`, `RiskArc.jsx`, `AlertsChart.jsx`, `EventStream.jsx`, `CampaignStrip.jsx` (new) | `/` |
| `src/components/alerts/AlertsPage.jsx`, `AlertTable.jsx`, `AlertDrawer.jsx`, `RiskBreakdown.jsx`, `ZScoreBars.jsx`, `alertFilters.js` (new) | `/alerts` |
| `src/components/entities/EntityPage.jsx` (new) | `/entities/:type/:key` |
| `src/components/scenarios/DetectionLab.jsx` (new), `AttackPanel.jsx` (modify: tabs) | `/scenarios` |
| `src/components/reports/ReportsPage.jsx` (rewrite) | `/reports` |
| `src/components/settings/SettingsPage.jsx` (new) | `/settings` |
| `src/App.jsx`, `src/main.jsx` (modify) | routes, remove ambient bg + overlay |
| tests: `src/lib/wsValidators.test.js` (extend), `src/lib/format.test.js`, `src/components/alerts/alertFilters.test.js` (new) | |

---

### Task 1: Theme tokens, legacy aliases, glow neutralisation

- [ ] Rewrite `src/index.css` `@theme` block: new tokens (`bg-0..3`, `line`, `line-strong`, `fg-0..3`, `accent`, `accent-hover`, `sev-critical/high/medium/low/info`) and legacy aliases (`bg-base→bg-0`, `bg-panel→bg-1`, `bg-elevated→bg-2`, `bg-sunken→#070708`, `border-subtle→line`, `border-strong→line-strong`, `neon-green→#22c55e`, `neon-red→#ef4444`, `neon-orange→#f97316`, `neon-blue→#6366f1`, `neon-cyan→#6366f1`, `neon-violet→#a78bfa`, `fg-primary→fg-0`, `fg-secondary→fg-1`, `fg-muted→fg-2`, `fg-faint→fg-3`). Keep only `blink`, `shimmer`, `anomaly-pulse`, `recovery-pulse`, `recovery-line` keyframes (legacy panels reference them); the rest removed.
- [ ] Body: flat `bg-0`, no gradients, no `::before` grid, no `::after` noise.
- [ ] Utilities: `.glass-panel`, `.glass-deep` → `background: var(--color-bg-1)`; `.text-glow-*`, `.ring-glow-*`, `.shimmer-line`, `.shine-sweep::after` → empty; `[class*="shadow-[0_0_"] { box-shadow: none !important }`; `.transition-cyber` → 150ms; `.scrollbar-cyber` neutral thumb; `@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; transition: none !important } }`; `@media print` rules for `.print-report`.
- [ ] `src/main.jsx`: remove `ThreatReactionOverlay`. `src/App.jsx`: remove `AmbientBackground`.
- [ ] Run `npm run build` — Expected: success. Commit.

### Task 2: Format helpers + validators + store slices

- [ ] `src/lib/format.js`:
```js
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
export const severityRank = (s) => { const i = SEVERITY_ORDER.indexOf(s); return i === -1 ? SEVERITY_ORDER.length : i; };
export const fmtTime = (iso) => iso ? new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';
export function fmtAgo(iso, now = Date.now()) { if (!iso) return ''; const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000)); if (s < 60) return `${s}s`; const m = Math.floor(s / 60); if (m < 60) return `${m}m`; const h = Math.floor(m / 60); if (h < 24) return `${h}h`; return `${Math.floor(h / 24)}d`; }
export const fmtNum = (n) => (n == null ? '—' : n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : String(n));
export const fmtPct = (x) => (x == null ? '—' : `${(x * 100).toFixed(x >= 0.995 ? 1 : 0)}%`);
export const titleCase = (s) => String(s ?? '').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
```
  Test `src/lib/format.test.js`: `fmtAgo` buckets, `severityRank` order, `fmtNum` thresholds, `titleCase`.
- [ ] `wsValidators.js`: add `isValidAlertFrame` (`type ∈ alert_new|alert_update`, `alert` object with string `id`, `threat_type`, `severity`, number `risk`, object `entity`), `isValidStatsFrame` (`type==='stats'`, `data` object with number `events_ingested`), `isValidConfigFrame` (`type==='config_update'`, `thresholds` object). Tests in `wsValidators.test.js`.
- [ ] `useRealtimeEvents.js`: state gains `alerts: {}` (id → alert), `stats: null`, `config: null`; on alert frames `alerts = { ...prev.alerts, [alert.id]: alert }` capped at 1000 by dropping oldest `first_seen`; `maxEvents` default 500; on `ws.onopen` fetch `/api/v1/alerts?limit=500` and `/api/v1/config/thresholds` via `api.js` and merge. `RealtimeProvider` passes `alerts, stats, config`. Selectors: `selectAlerts` (map), `selectStats`, `selectConfig`. `selectAlertList` memoised: sorted by `last_seen` desc.
- [ ] `api.js`: add `getThresholds`, `putThresholds(patch)`, `resetThresholds`, `listAlerts(params)`, `getAlert(id)`, `patchAlert(id, patch)`, `alertsSummary`, `trafficAttack({kind,duration_s,speed})`, `trafficStop`, `trafficStats`, `trafficConfig(cfg)`, `detectionStatus`, `detectionCampaigns`, `detectionEntity(type,key)`, `detectionRetrain`, `incidentReport(since)`, `incidentReportMarkdown(since)`. All via `withApiBase(`${API_PREFIX}...`)`.
- [ ] `npm test` green. Commit.

### Task 3: UI primitives

- [ ] `ui/table.jsx`: `Table`, `THead`, `TBody`, `TR` (`data-active`, `onClick`, `tabIndex`), `TH` (sortable: `onSort`, `dir`), `TD`. Dense: `text-[12.5px]`, row `h-9`, sticky header `bg-1`. Export `useVirtualRows(containerRef, rowHeight, count, overscan=8)` returning `{start, end, padTop, padBottom, onScroll}`.
- [ ] `ui/drawer.jsx`: right slide-over (`fixed inset-y-0 right-0 w-[520px] max-w-full`), backdrop, `Esc` closes, focus trap minimal (focus first focusable), framer 150ms x-translate.
- [ ] `ui/tabs.jsx`: `Tabs`, `TabList`, `Tab`, `TabPanel` (roving tabindex, aria).
- [ ] `ui/slider.jsx`: labelled range with numeric input, `min/max/step/value/onChange`, shows current value.
- [ ] `ui/stat.jsx`: `Stat({label, value, hint, tone, delta, spark})` tile.
- [ ] `ui/sparkline.jsx`: Recharts `LineChart` 80×24, no axes, single muted line.
- [ ] `ui/kbd.jsx`, `ui/empty.jsx` (empty state with icon + text).
- [ ] `badge.jsx`: variants renamed to semantic (`critical/high/medium/low/info/accent/neutral/outline`) while keeping old names as aliases (`destructive→critical`, `warning→high`, `success→low`, `info/cyan/default→accent`, `violet→neutral`); drop `glow` compound styles. `button.jsx`: `default` = accent fill, others flat; drop glow shadows.
- [ ] Commit.

### Task 4: Shell — Sidebar rail, Topbar stats strip, Command palette

- [ ] `Sidebar.jsx`: 56px rail, expands to 208px on hover (CSS `group` width transition) or when pinned (localStorage `sentinel.sidebar.pinned`). Groups: Detect (Overview `/`, Alerts `/alerts`), Simulate (Scenarios, Systems, Infrastructure, Honeypot), Operate (Reports, Settings). Active = accent left bar + `bg-2`. Prefetch kept.
- [ ] `Topbar.jsx`: left = page title (from route map) + breadcrumb; centre = stats strip (`ev/s`, `open alerts` split by severity dots, `suppression %`, WS status dot); right = `⌘K` button, mode toggle, demo reset, clock. Reads `selectStats`, `selectAlertList`.
- [ ] `CommandPalette.jsx`: `⌘K`/`Ctrl+K` opens; fuzzy list of actions: navigate pages; "Launch: <kind>" for each `SESSION_KINDS` → `trafficAttack`; "Acknowledge alert <id prefix>" for open alerts; "Set alert threshold …" opens settings; "Reset demo". Keyboard nav, `Enter` runs, `Esc` closes.
- [ ] Commit.

### Task 5: Overview page

- [ ] `overview/KpiRow.jsx`: 6 `Stat`s from `stats`+alerts: Events ingested, ev/s (spark of last 60 stats samples kept in a ref), Open alerts (by-severity dots), Suppression, Active sessions, MTTD (from `/reports/incident` polled 10s).
- [ ] `overview/RiskArc.jsx`: flat SVG arc of `riskScore` with label and tone by threshold from `config` (`sev_*`).
- [ ] `overview/AlertsChart.jsx`: Recharts stacked `AreaChart` of alerts by severity over the last 15 min (1-min buckets from `first_seen`), muted severity colours, no gradients.
- [ ] `overview/EventStream.jsx`: virtualised table of `events` with filters: severity multiselect chips, type select, text search (message/ip/user) — all applied; row click → `/entities/ip/<ip>`. Shows `threat_type` + `risk` pill from the paired pipeline frame (store keeps `eventsMeta[event.id] = {threat_type, risk_score, severity}` — add to store in Task 2 if missed).
- [ ] `overview/CampaignStrip.jsx`: polls `detectionCampaigns` every 5s; cards with distinct IPs/subnets/users/fail ratio, click → `/entities/campaign/<id>`.
- [ ] `OverviewPage.jsx` layout: KPI row; grid `[2fr 1fr]`: left AlertsChart + EventStream; right RiskArc + CampaignStrip + `AICopilotPanel` (existing). Wire route `/`.
- [ ] Commit.

### Task 6: Alerts page + explain drawer

- [ ] `alerts/alertFilters.js`: `applyFilters(list, {severity:Set, status:Set, type:Set, entityType:Set, q})`, `sortAlerts(list, key, dir)` (keys: severity→rank, risk, count, last_seen, threat_type). Tests.
- [ ] `alerts/AlertTable.jsx`: columns Sev · Type · Entity · Risk (bar) · Count · Age · Status · MITRE. Keyboard: `j/k` move, `Enter` open, `a` acknowledge, `r` resolve, `f` false-positive. Virtualised.
- [ ] `alerts/RiskBreakdown.jsx`: horizontal bars for `risk_breakdown` against `RISK_BUDGET` (hard-coded mirror of backend budget) with values.
- [ ] `alerts/ZScoreBars.jsx`: diverging bars for `zscores` (clamped ±4), label per feature, tooltip with feature value.
- [ ] `alerts/AlertDrawer.jsx`: header (severity, type, entity link, risk, count, first/last seen, MITRE chips, campaign link); sections: Risk breakdown; Signals fired (chips); Behaviour vs baseline (ZScoreBars + feature table); Recommended actions (from `alert.actions`, priority-sorted); Status buttons (`acknowledge / investigating / resolve / false positive`) → `patchAlert`; notes textarea (save on blur); sample message.
- [ ] `alerts/AlertsPage.jsx`: facet bar (chips per severity/status/type/entityType with counts), search, sort; table; drawer bound to `?alert=<id>` search param. Wire `/alerts`.
- [ ] Commit.

### Task 7: Entity page

- [ ] `entities/EntityPage.jsx`: fetch `detectionEntity(type,key)` on mount and every 5s; header; feature table with z-score and baseline mean±std; sparklines from a local ring of the last 60 samples; events table (last 100); related alerts (reuse `AlertTable` compact); for `campaign` type show members + fingerprint. Wire `/entities/:type/:key`.
- [ ] Commit.

### Task 8: Scenarios — Detection Lab tab + catalog wiring

- [ ] `scenarios/attacks.js`: mark `port-scan`, `cred-stuffing` as `active: true` with `trafficKind: 'port_scan' | 'credential_stuffing'`; add `{ id: 'low-slow', name: 'Low & Slow Brute Force', category: 'AUTH', active: true, trafficKind: 'low_slow_brute_force', desc: 'One account, one attempt per rotating IP, 30 s cadence' }`; each active entry gets `detector: 'port_scan' | 'credential_stuffing' | 'low_slow_brute' | 'lexical+ml'`.
- [ ] `api.triggerAttack`: if the attack has `trafficKind` → `trafficAttack({kind, duration_s: 20, speed})` where `speed` = 15 for low-slow, 3 otherwise.
- [ ] `scenarios/DetectionLab.jsx`: pick a kind, duration, speed; launch; live scoreboard: events emitted (from `stats.active_sessions`), first alert time (watch `alerts` for matching `threat_type` after launch ts), signals fired (union), risk trajectory sparkline (from pipeline frames matching the session's label — store keeps `eventsMeta`).
- [ ] `AttackPanel.jsx`: wrap existing content in `Tabs` (`Catalog` | `Detection Lab`).
- [ ] Commit.

### Task 9: Reports page

- [ ] `reports/ReportsPage.jsx` rewrite: fetch `incidentReport()`; sections: metrics tiles; alerts by severity/type (bar lists); top attackers / top targets tables (entity links); MITRE coverage grid; timeline list; actions taken. Toolbar: JSON, CSV (timeline), Markdown (from `incidentReportMarkdown`), Print/PDF (`window.print()` with `.print-report` class). Wire `/reports`.
- [ ] Commit.

### Task 10: Settings page

- [ ] `settings/SettingsPage.jsx`: loads `getThresholds`; groups: Alerting, Severity cut points, Decision tiers, Port scan, Credential stuffing, Low & slow, Baseline, Campaign, Isolation forest — one `Slider` per field (min/max from a local schema table). Live preview: "with these values N of the last M events would alert" = count of `eventsMeta` risk ≥ `alert_min_risk` draft. Buttons: Apply (`putThresholds` diff), Reset, Retrain forest (`detectionRetrain`). Traffic section: rate/benign ratio sliders + pause toggle (`trafficConfig`). Wire `/settings`; remove `/support`.
- [ ] Commit.

### Task 11: Verify, lint, docs

- [ ] `npm run lint`, `npm test`, `npm run build` all green.
- [ ] Manual run against backend: every route renders; launch each kind from Detection Lab and confirm alert appears in `/alerts`, drawer shows breakdown, entity page opens, settings change is reflected.
- [ ] Update `sentinel-ai-frontend/README.md` and `docs/ARCHITECTURE.md` §6 (pages, store slices, primitives).
- [ ] Commit.
