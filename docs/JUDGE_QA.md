# SentinelAI — Judge Q&A Prep

Answers are written to be **confident, specific, and honest under pressure**. The strongest move is to sound like engineers who know exactly what's real. Never bluff a hard fact you can't back up — pivot to the real engineering, which is genuinely strong.

---

## The one question you WILL get

**"Is this real production data / real attackers, or is it simulated?"**

> "The detection engine, risk scoring, signature learning, honeypot analysis and dashboards are all real, production-grade code — that's the hard part and it's done. For the demo we drive it with a high-fidelity traffic-and-attack generator that reproduces real banking telemetry and real attack techniques — credential stuffing over residential-proxy pools, low-and-slow brute force, port recon — so we can show every vector on demand instead of waiting for a real incident. The engine can't tell the difference; it ingests the same event schema you'd get from real auth logs, a Kafka stream, or a WAF. Point it at production log sources and it works unchanged — we have a Kafka ingestor and an NDJSON replay endpoint for exactly that."

**Why this wins:** it's true, it's strong, and it turns "is it fake?" into "look how production-ready the pipeline is." Do **not** claim a real bank client or real criminals — if pressed, that unravels and you lose credibility for the whole project.

---

## Detection / ML

**"How is this different from a normal SIEM or firewall rule?"**
> "Static rules fire on a fixed threshold — 10 failed logins in 60 seconds. Attackers just throttle below it. We don't use a fixed count; we measure **deviation from each entity's behavioural baseline** with online z-scores, plus an unsupervised isolation forest for novel patterns, plus campaign correlation across many IPs. So a low-and-slow attack that never trips any single threshold still stands out as anomalous behaviour."

**"What ML are you actually using?"**
> "Three complementary scorers that vote. One: per-entity statistical baselines — Welford online mean/variance, z-scored per feature, per IP, per user, per /24 subnet. Two: a scikit-learn **Isolation Forest** trained on benign traffic for unsupervised anomaly detection — that's our zero-day path. Three: a campaign clusterer that groups events by client fingerprint. Then dedicated detectors for port scan, credential stuffing and low-and-slow combine with those into a final risk score."

**"What features do you extract?"**
> "Eleven per entity: failure ratio, attempts per minute, distinct users, distinct IPs, distinct ports, port sequentiality, inter-arrival mean and standard deviation, user-agent entropy, hour-of-day deviation, and endpoint diversity. Computed over a 300-second sliding window per IP, per user, and per /24."

**"How do you avoid false positives on real customers?"**
> "The baseline is learned from the population of legitimate traffic, so normal customer behaviour sits near zero deviation. On our eval, benign traffic has a **0% false-alert rate**. And signatures — the learned fast-path — key only on automation-tool fingerprints like a `python-requests` user-agent, never anything a real browser carries, so learning can never flag a legitimate user."

**"What's your accuracy?"**
> "On a 5,000-event evaluation, 85% benign: 100% precision, 94–97% recall across port scan, credential stuffing, low-and-slow and DDoS, with first detection in 5–8 events. It's reproducible — `python -m scripts.eval_detection`."

**"Isolation forest on your own synthetic data — isn't that circular?"**
> "Fair — the forest is trained on *benign* traffic only, and it flags outliers regardless of label, so it generalises to patterns we didn't script. The honest next step for production is training baselines on the customer's real historical logs; the pipeline is built for that — it's the same feature vectors."

---

## The signature / learning feature

**"How is a signature different from an antivirus signature?"**
> "Same idea — a durable fingerprint of a known-bad actor — but ours are **learned automatically** from confirmed detections, not hand-written, and they key on behavioural indicators (tool user-agent, endpoint, source /24 for network attacks). Once learned, a repeat attack is caught on the first event instead of after the window rebuilds. They persist to disk, so learning survives restarts."

**"Could an attacker poison your signatures?"**
> "We only learn from threats that already crossed the alert threshold with multiple independent signals agreeing — not from a single event — and we never learn a real-browser fingerprint. So an attacker can't teach it to flag legitimate traffic. Worst case, they change their tool UA and we simply detect them again behaviourally and learn the new one."

---

## Alerts / operations

**"How do you handle alert fatigue?"**
> "Two ways. Sub-threshold events are suppressed entirely — you saw ~100% suppression on benign traffic. And alert-worthy events are **de-duplicated**: a campaign across thousands of rotating IPs collapses into one alert with a growing count, keyed on the entity or campaign, not one alert per packet."

**"Can analysts tune it?"**
> "Every threshold is runtime-configurable from the Settings page — alert threshold, severity cut-points, per-detector sensitivity, the isolation-forest contamination, retrain interval — and changes hot-reload and broadcast to every connected client. No redeploy."

**"What actions can it take — is it automated response?"**
> "The decision engine produces priority-ordered response actions — block IP, rate-limit, isolate service, quarantine host, rotate credentials, escalate — with a human-readable reason for each. Today they're recommended and shown in the alert; wiring them to real enforcement (a firewall API, an IAM call) is a config change, not a rearchitecture."

---

## Honeypot

**"Is the honeypot real or scripted?"**
> "The honeypot *analysis* is real — pattern extraction, TTP mapping, risk scoring of the adversary's behaviour, session recording. In the demo the adversary interaction is driven by our attack generator; in production you'd point it at an actual decoy host. The value we're showing is the analysis and correlation layer, which is engine code."

**"Why engage a honeypot at all?"**
> "Two reasons: it buys the SOC time by keeping the attacker busy on decoy data, and it produces high-fidelity intelligence — exact TTPs, tooling, targets — that you can't get from a blocked connection."

---

## Architecture / scale

**"Does it scale to 65,000 TPS?"**
> "The demo runs at demo rate so you can see it, but the architecture is built for throughput: async FastAPI, a Kafka ingestor for the event stream, bounded in-memory sliding windows so memory stays flat, and stateless scoring that shards by entity. The honest answer: we've engineered for it and validated the pipeline; a 65k-TPS load test is the next milestone, and nothing in the design blocks it."

**"What's the stack?"**
> "Backend: Python, FastAPI, asyncio, Pydantic, scikit-learn, numpy. Frontend: React, Vite, Tailwind, Recharts, WebSocket streaming. Kafka for ingestion, Docker and Kubernetes manifests for deploy, CI with lint, tests and coverage gates. ~60 backend tests, 85% coverage."

**"How does data get in?"**
> "Three paths, same normalised event schema: the live WebSocket pipeline, a Kafka consumer for `raw.events`, and an NDJSON replay endpoint for batch or forensic re-ingestion. Plugging in real syslog/WAF/auth logs is a normaliser, not a redesign."

**"What if the ML model is wrong / the backend goes down?"**
> "Detection degrades gracefully — the rule and lexical signals still work without the ML scorers, and if the isolation forest isn't fitted it simply abstains. The WebSocket client reconnects automatically. Every frame is schema-validated before broadcast, so a bad payload can't corrupt the dashboard."

---

## Business / product

**"Who's the customer and why would they buy this?"**
> "Tier-1 banks and fintechs whose SOCs are drowning in false positives and still missing low-and-slow campaigns. The pitch is: fewer alerts, but the *right* ones, each explainable and MITRE-mapped, plus a system that gets faster as it sees more attacks."

**"What's the moat / what's hard here?"**
> "The multi-signal fusion that keeps precision at 100% while catching stealthy attacks, the automatic signature learning, and the explainability layer — the per-factor risk breakdown and z-score view that let an analyst trust and act on an alert in seconds. Pretty dashboards are easy; the detection engine and its explainability are the hard, defensible part."

**"What would you build next?"**
> "Train baselines on a customer's real historical logs; wire the response actions to live enforcement; a supervised classifier layer on labelled incident data to complement the unsupervised path; and a 65k-TPS load validation. The platform is designed so each of those is an extension, not a rewrite."

---

## If you get stuck / don't know

> "Great question — I don't want to overclaim. What I can tell you precisely is [what's real]. [The thing you're asking about] is on our roadmap, and the architecture is built so it drops in without a rewrite."

Honesty + a crisp scope line beats a bluff every time.
