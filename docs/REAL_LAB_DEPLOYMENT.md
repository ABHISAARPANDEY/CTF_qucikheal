# SentinelAI Real Lab Deployment (Phase A -> B -> C)

This guide upgrades SentinelAI from pure simulation into a real telemetry SOC lab in three phases.

---

## Phase A — Containerized Baseline + Kafka-Ready

### What you get

- Containerized frontend + backend
- Kafka-compatible broker (Redpanda)
- Kafka UI console
- Backend Kafka ingestion path enabled

### Start Phase A

```bash
docker compose -f docker-compose.phase-a.yml up --build -d
```

### URLs

- SentinelAI frontend: `http://localhost:8080`
- Backend API: `http://localhost:8000`
- Kafka console: `http://localhost:8090`
- Kafka external listener: `localhost:19092`

### Stop

```bash
docker compose -f docker-compose.phase-a.yml down
```

---

## Phase B — Real Attack Lab (Juice Shop + Real Event Feed)

### What you get

- OWASP Juice Shop service in the same lab network
- Lab event producer sending realistic web attack signals to Kafka topic `raw.events`
- Backend consumes Kafka events, runs real pipeline detection, and streams to dashboard

### Start Phase B

Use both compose files together:

```bash
docker compose -f docker-compose.phase-a.yml -f docker-compose.phase-b.yml up --build -d
```

### URLs

- Juice Shop: `http://localhost:3000`
- SentinelAI: `http://localhost:8080`

### How data flows

1. `lab-producer` writes attack-like events to Kafka topic `raw.events`
2. backend Kafka ingestor consumes events
3. backend normalizes them into canonical `Event`
4. pipeline runs detection/decision/response/explanation
5. dashboard updates via `/ws/live`

### Safe testing note

Run tools only in isolated local lab targets (e.g., Juice Shop container), never on unauthorized systems.

---

## Phase C — Kubernetes Deployment

K8s manifests are provided in `deploy/k8s/`.

### Apply app stack

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/backend.yaml
kubectl apply -f deploy/k8s/frontend.yaml
kubectl apply -f deploy/k8s/ingress.yaml
```

### Kafka in Phase C

Recommended: managed Kafka or operator-based Kafka (Strimzi/Confluent), then set:

- `KAFKA_ENABLED=true`
- `KAFKA_BOOTSTRAP_SERVERS=<broker-host>:9092`
- `KAFKA_TOPIC_RAW_EVENTS=raw.events`
- `KAFKA_GROUP_ID=sentinelai-pipeline`

in backend deployment env.

---

## Environment Variables (Backend)

Add to `.env` (local) or deployment env:

```env
KAFKA_ENABLED=true
KAFKA_BOOTSTRAP_SERVERS=redpanda:9092
KAFKA_TOPIC_RAW_EVENTS=raw.events
KAFKA_GROUP_ID=sentinelai-pipeline
```

---

## Verification Checklist

- `GET /api/v1/health` returns `ok`
- `GET /api/v1/ready` returns `ready`
- Dashboard threat feed updates from Kafka-driven events
- Systems/Honeypot/Reports continue updating
- WebSocket reconnect behavior still stable

