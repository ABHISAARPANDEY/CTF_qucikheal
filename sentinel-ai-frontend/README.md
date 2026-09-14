# SentinelAI Frontend — SOC Console

React 19 + Vite + Tailwind v4 single-page SOC console for the SentinelAI
detection backend. Calm, dense, production-style dark UI (no neon/glows).

## Pages

- **Overview** (`/`) — KPI row, risk arc, alerts-over-time, virtualised live
  event stream with severity/type/text filters, active campaigns, AI copilot.
- **Alerts** (`/alerts`) — faceted, keyboard-driven triage queue with an
  explainability drawer (risk breakdown, fired signals, feature-vs-baseline
  z-scores, recommended actions, notes).
- **Entities** (`/entities/:type/:key`) — per ip/user/subnet/campaign drill-down.
- **Scenarios** (`/scenarios`) — attack catalog + Detection Lab (live scoreboard).
- **Reports** (`/reports`) — incident summary + JSON/CSV/Markdown/PDF export.
- **Settings** (`/settings`) — runtime detection thresholds + traffic controls.

## Realtime

WebSocket `/ws/live`. Store slices: `events` + `eventsMeta`, `alerts`, `stats`
+ `statsHistory`, `config`, plus the original scenario/system/honeypot feeds.
Frame validators guard every update; alerts and thresholds also hydrate over
REST on connect.

## Commands

```
npm install
npm run dev      # vite dev server (proxies /api and /ws to :8000)
npm test         # vitest
npm run lint
npm run build
```

Point at a backend with `VITE_API_BASE_URL` (defaults to same-origin / :8000 in dev).

---

# React + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the ESLint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io) in your project.
