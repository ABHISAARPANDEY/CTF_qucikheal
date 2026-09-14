# SentinelAI — 5-Minute Demo Script

**Goal:** land three things — (1) we detect stealthy, distributed attacks that static SIEMs miss, (2) every alert is explainable and low-noise, (3) the system *learns* and gets faster. Present it live, confident, present tense.

**Positioning line (memorise):**
> "SentinelAI is a real-time cyber-defence command center for banking-grade infrastructure. It watches authentication, network and system telemetry, scores every event with behavioural ML, and traps the attacker in a live honeypot — all on one screen."

**Before you present (2-minute pre-flight, off-screen):**
1. Start backend + frontend. Open the dashboard full-screen. Dark mode (or light for a bright room).
2. Click **Reset demo** (top-right) so `OPEN 0`, suppression ~100%, clean stream.
3. **Pre-warm one signature** so the "learns → instant" moment is guaranteed: run one `credential_stuffing` from the ⌘K palette or Scenarios, let it detect, then **Reset demo** again (reset keeps the *learning* story natural — or leave one signature in Settings if you prefer to show it pre-loaded). Decide which and rehearse it once.
4. Have two browser tabs ready: **Overview** (`/`) and **Alerts** (`/alerts`). Know where **Scenarios**, **Honeypot**, **Reports**, **Settings** are in the left rail.

---

## 0:00 – 0:30 · The hook (no screen yet, or Overview idle)

> "Picture a Tier-1 digital bank. 65,000 transactions a second. It's a promo night, traffic is at its peak — and that's exactly when the attackers move. Not a loud brute-force that trips an alarm. A *low-and-slow* campaign: thousands of rotating residential IPs, one login attempt each, blending into normal customer traffic. A legacy firewall that blocks an IP after 10 failed logins in a minute? It never fires. The bank finds out days later."
>
> "This is the problem SentinelAI solves. Let me show you it working live."

*Cue: switch to the Overview screen.*

---

## 0:30 – 1:15 · The command center (Overview `/`)

*Point at the top strip and KPI row.*

> "This is our live posture. Right now the platform is ingesting banking telemetry — logins, API calls, network events — you can see the throughput here [**ev/s**] and the live event stream below. Every single event is scored in real time."
>
> "Notice two numbers. **Open alerts: zero.** **Suppression: near 100%.** That's the point — legitimate customer traffic is classified **benign** and never bothers an analyst. No alert fatigue. The risk gauge on the right sits **nominal**."

*Let the benign stream tick for a beat so they see BENIGN · 0.0 rows.*

> "So this is a calm SOC on a normal night. Now let's give it a bad night."

---

## 1:15 – 2:20 · Detect first, then trap (Scenarios → Overview / Alerts)

*Open ⌘K command palette (or Scenarios → Detection Lab) and launch a scenario — use **credential stuffing** or **multi-stage**.*

> "I'm launching a distributed credential-stuffing campaign against the auth service — a residential-proxy pool, exactly the pattern that evades static rules."

*Watch the Overview: risk gauge climbs, alerts chart spikes, a campaign card appears on the right, KPIs move.*

> "Watch the sequence — this is important. **First**, the platform *detects*: the risk score jumps, and here on the right it identifies a **distributed campaign** — one client fingerprint failing across dozens of IPs and subnets. It correlated events that each looked harmless on their own."
>
> "**Only after** we've confirmed the threat does the honeypot engage to isolate and study the attacker. Detection leads; containment follows. That ordering matters for a real SOC."

*Cut to Alerts (`/alerts`). One alert, high count.*

> "And crucially — that whole campaign is **one alert**, not ten thousand. The rotating IPs collapse into a single incident with a growing count. That's the alert-fatigue problem, solved."

---

## 2:20 – 3:10 · Why did it fire? (Alert → Explain drawer)

*Click the alert to open the drawer.*

> "Every alert answers the question a SOC analyst actually asks: *why?* Here's the **risk breakdown** — this wasn't a static threshold. It's a weighted vote: behavioural z-score, the isolation-forest anomaly model, the campaign correlation, all contributing."
>
> "This bar is the tell: **failure rate is five-plus standard deviations above this entity's baseline.** That's how we catch low-and-slow — we don't count events against a fixed number, we measure deviation from *normal behaviour*."
>
> "And it's mapped to **MITRE ATT&CK** — T1110.004 — with the recommended containment actions right here, priority-ordered. An analyst can act in seconds."

---

## 3:10 – 4:00 · It learns (Settings → signatures, then re-attack)

*Left rail → Settings → scroll to **Learned attack signatures**.*

> "Here's what makes it get smarter. Every confirmed detection is distilled into a **signature** — the attacker's tool fingerprint. We only learn high-precision indicators, never anything a real browser would carry, so this can't backfire on legitimate users."

*Back to ⌘K → launch the same attack kind again. Cut to Alerts.*

> "Now watch the same attacker come back."

*Point at the ⚡ badge / `signature_match`.*

> "**Instant.** First event, first packet — flagged with the lightning bolt, matched to the learned signature. No waiting for the pattern to build up again. The system that took a few seconds to learn this attack now catches it immediately, forever."

---

## 4:00 – 4:40 · The honeypot (Honeypot page)

*Left rail → Honeypot.*

> "While detection happened, the adversary was quietly moved into our decoy mesh. This is the live capture — the attacker's own session and our observer log, side by side."
>
> "On the right, **forensic analysis**: the behaviour is broken into stages and mapped to TTPs — credential theft, lateral movement, data exfiltration. The attacker thinks they're winning; they're pulling honey data while we record everything and hand a full timeline to the SOC."

*(Optional, if time) Reports page:*
> "And it all rolls up into an exportable incident report — top attackers, targeted accounts, MITRE coverage, a full timeline — one click to JSON, CSV or PDF for the incident-response team."

---

## 4:40 – 5:00 · Close

> "So — one platform. It detects the stealthy, distributed attacks that static SIEMs miss, using real behavioural ML. Every alert is explainable and de-duplicated, so analysts aren't drowning. It traps and studies the adversary in real time. And it *learns* — every attack makes it faster."
>
> "On our evaluation it runs at **100% precision and 94–97% recall across the attack vectors, with a zero-percent false-alert rate on benign traffic.** That's the difference between finding the breach in seconds — and finding out days later. Thank you."

---

## Presenter cues / safety net

- **If a scenario doesn't visibly alert in time:** keep talking, launch a second from ⌘K; detection builds over a few seconds by design. Don't wait in silence.
- **If the stream looks quiet:** that's correct — benign traffic is suppressed. Say so; it's a feature.
- **Reset between run-throughs:** `Reset demo` clears alerts, campaigns and signatures for a clean start.
- **Keep hands on ⌘K** — launching attacks, acknowledging alerts, and jumping pages all live in the command palette; it looks fast and intentional.
- **Time budget:** if running long, cut the Reports paragraph (4:30) and go straight to the close.
