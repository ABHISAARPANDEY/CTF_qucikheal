"""Banking infrastructure simulation engine.

Continuously emits per-system telemetry (``system_update`` frames) over the
existing WebSocket transport so connected dashboards see live host metrics
even when no detection pipeline is firing.

Topology
--------
Four systems mirror the dashboard's Infrastructure View::

    api_gateway          (Cluster A · Edge & Identity)
    auth_service         (Cluster A · Edge & Identity)
    transaction_service  (Cluster B · Core Banking)
    database             (Cluster B · Core Banking)

State machine
-------------
At rest every system sits in **normal** state — CPU drifts gently around
its baseline, requests-per-second wobble, processes are the legitimate
inventory.

Calling :meth:`BankingSimulator.inject_attack` lifts the targeted system
into **warning** or **critical** for ``attack_duration`` seconds:

    ddos          → api_gateway          (rogue_curl_flood, suspicious_script.sh)
    brute_force   → auth_service         (credential_stuffer.py, suspicious_script.sh)
    login_flood   → auth_service         (credential_stuffer.py)
    sql_injection → database             (sql_probe.sh, suspicious_script.sh)
    tx_replay     → transaction_service  (tx_replay_worker)
    crypto_miner  → any system           (crypto_miner)

Lateral spread bumps the paired system in the same cluster to **warning**.

Wire format (one frame per system per tick)
-------------------------------------------
::

    {
      "type": "system_update",
      "system": "api_gateway",
      "data": {
        "cpu": 87.4,
        "requests": 9215,
        "latency_ms": 312,
        "error_rate": 2.84,
        "status": "critical",
        "uptime_s": 482915,
        "anomalies": ["high_cpu_usage", "traffic_spike", "unknown_process"],
        "processes": [
            {"name": "nginx", "pid": 4412, "cpu": 18.2, "status": "ok",        "malicious": false},
            {"name": "rogue_curl_flood", "pid": 33214, "cpu": 41.7,
             "status": "malicious", "malicious": true,
             "summary": "Synthetic HTTP flood saturating edge listener pool"}
        ],
        "ts": "2026-05-02T13:51:08.412Z"
      }
    }
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger(__name__)

                                                                              

API_GATEWAY = "api_gateway"
AUTH_SERVICE = "auth_service"
TRANSACTION_SERVICE = "transaction_service"
DATABASE = "database"

SYSTEMS: tuple[str, ...] = (
    API_GATEWAY,
    AUTH_SERVICE,
    TRANSACTION_SERVICE,
    DATABASE,
)


@dataclass(frozen=True)
class SystemSpec:
    """Static per-system metadata + baselines."""

    id: str
    display_name: str
    base_cpu: float                   
    base_rps: int                             
    base_latency_ms: int                     
    base_processes: tuple[dict[str, Any], ...]
    cluster_peer: str                                                   


SPECS: dict[str, SystemSpec] = {
    API_GATEWAY: SystemSpec(
        id=API_GATEWAY,
        display_name="API Gateway",
        base_cpu=24.0,
        base_rps=1840,
        base_latency_ms=22,
        cluster_peer=AUTH_SERVICE,
        base_processes=(
            {"name": "nginx",          "pid": 4412, "role": "edge proxy"},
            {"name": "gateway-edge",   "pid": 4523, "role": "router"},
            {"name": "rate-limiter",   "pid": 4634, "role": "guard"},
            {"name": "tls-terminator", "pid": 4711, "role": "crypto"},
        ),
    ),
    AUTH_SERVICE: SystemSpec(
        id=AUTH_SERVICE,
        display_name="Auth Service",
        base_cpu=18.0,
        base_rps=640,
        base_latency_ms=18,
        cluster_peer=API_GATEWAY,
        base_processes=(
            {"name": "auth_service",  "pid": 5101, "role": "idp"},
            {"name": "oauth-proxy",   "pid": 5208, "role": "proxy"},
            {"name": "session-cache", "pid": 5311, "role": "cache"},
            {"name": "mfa-vault",     "pid": 5404, "role": "secrets"},
        ),
    ),
    TRANSACTION_SERVICE: SystemSpec(
        id=TRANSACTION_SERVICE,
        display_name="Transaction Service",
        base_cpu=30.0,
        base_rps=920,
        base_latency_ms=42,
        cluster_peer=DATABASE,
        base_processes=(
            {"name": "tx-engine",      "pid": 6201, "role": "core"},
            {"name": "payment-router", "pid": 6312, "role": "router"},
            {"name": "ledger-sync",    "pid": 6418, "role": "sync"},
            {"name": "fraud-scorer",   "pid": 6527, "role": "ml"},
        ),
    ),
    DATABASE: SystemSpec(
        id=DATABASE,
        display_name="Core Database",
        base_cpu=26.0,
        base_rps=2680,
        base_latency_ms=8,
        cluster_peer=TRANSACTION_SERVICE,
        base_processes=(
            {"name": "db_engine",    "pid": 7101, "role": "rdbms"},
            {"name": "postgresql",   "pid": 7202, "role": "primary"},
            {"name": "pgbouncer",    "pid": 7314, "role": "pool"},
            {"name": "wal-archiver", "pid": 7427, "role": "archive"},
        ),
    ),
}

                                                                              


@dataclass(frozen=True)
class AttackSpec:
    """Static description of one attack vector."""

    kind: str
    primary_system: str
    cpu_boost: tuple[float, float]                                          
    rps_multiplier: tuple[float, float]
    latency_multiplier: tuple[float, float]
    error_rate_range: tuple[float, float]
    anomalies: tuple[str, ...]
    rogue_processes: tuple[dict[str, Any], ...]


_ATTACKS: dict[str, AttackSpec] = {
    "ddos": AttackSpec(
        kind="ddos",
        primary_system=API_GATEWAY,
        cpu_boost=(55.0, 72.0),
        rps_multiplier=(4.5, 7.5),
        latency_multiplier=(8.0, 14.0),
        error_rate_range=(2.4, 4.6),
        anomalies=("high_cpu_usage", "traffic_spike", "unknown_process"),
        rogue_processes=(
            {
                "name": "rogue_curl_flood",
                "role": "foreign · flood",
                "summary": "Synthetic HTTP flood saturating edge listener pool",
                "cpu_share": 0.45,
            },
            {
                "name": "suspicious_script.sh",
                "role": "foreign · payload",
                "summary": "Untracked shell binary spawned under nobody:nogroup",
                "cpu_share": 0.18,
            },
        ),
    ),
    "brute_force": AttackSpec(
        kind="brute_force",
        primary_system=AUTH_SERVICE,
        cpu_boost=(38.0, 55.0),
        rps_multiplier=(6.0, 12.0),                                        
        latency_multiplier=(2.5, 5.0),
        error_rate_range=(1.6, 3.0),
        anomalies=("login_flood", "high_cpu_usage", "unknown_process"),
        rogue_processes=(
            {
                "name": "credential_stuffer.py",
                "role": "foreign · brute",
                "summary": "Credential stuffing burst across rotating proxy pool",
                "cpu_share": 0.40,
            },
            {
                "name": "suspicious_script.sh",
                "role": "foreign · payload",
                "summary": "Lateral-movement helper invoking sudo with stolen creds",
                "cpu_share": 0.15,
            },
        ),
    ),
    "sql_injection": AttackSpec(
        kind="sql_injection",
        primary_system=DATABASE,
        cpu_boost=(50.0, 68.0),
        rps_multiplier=(2.0, 3.5),
        latency_multiplier=(6.0, 12.0),
        error_rate_range=(1.4, 3.2),
        anomalies=("abnormal_db_queries", "high_cpu_usage", "unknown_process"),
        rogue_processes=(
            {
                "name": "sql_probe.sh",
                "role": "foreign · sqli",
                "summary": "Boolean-blind SQLi probing /accounts/balance",
                "cpu_share": 0.42,
            },
            {
                "name": "suspicious_script.sh",
                "role": "foreign · payload",
                "summary": "Schema enumeration via UNION-based payloads",
                "cpu_share": 0.18,
            },
        ),
    ),
    "login_flood": AttackSpec(
        kind="login_flood",
        primary_system=AUTH_SERVICE,
        cpu_boost=(28.0, 45.0),
        rps_multiplier=(8.0, 16.0),
        latency_multiplier=(2.0, 3.5),
        error_rate_range=(0.9, 1.8),
        anomalies=("login_flood", "traffic_spike"),
        rogue_processes=(
            {
                "name": "credential_stuffer.py",
                "role": "foreign · brute",
                "summary": "Login attempt rate exceeded 10× baseline for 60s window",
                "cpu_share": 0.38,
            },
        ),
    ),
    "tx_replay": AttackSpec(
        kind="tx_replay",
        primary_system=TRANSACTION_SERVICE,
        cpu_boost=(40.0, 58.0),
        rps_multiplier=(2.5, 4.5),
        latency_multiplier=(4.0, 8.0),
        error_rate_range=(1.2, 2.8),
        anomalies=("traffic_spike", "unknown_process", "abnormal_db_queries"),
        rogue_processes=(
            {
                "name": "tx_replay_worker",
                "role": "foreign · replay",
                "summary": "Replaying signed envelopes with mutated nonces",
                "cpu_share": 0.35,
            },
        ),
    ),
    "crypto_miner": AttackSpec(
        kind="crypto_miner",
        primary_system=TRANSACTION_SERVICE,                                  
        cpu_boost=(48.0, 62.0),
        rps_multiplier=(1.0, 1.3),                               
        latency_multiplier=(1.4, 2.4),
        error_rate_range=(0.4, 1.0),
        anomalies=("high_cpu_usage", "unknown_process"),
        rogue_processes=(
            {
                "name": "crypto_miner",
                "role": "foreign · miner",
                "summary": "XMRig-class miner pegged to 4 cores via CPU affinity",
                "cpu_share": 0.55,
            },
            {
                "name": "suspicious_script.sh",
                "role": "foreign · payload",
                "summary": "Persistence loader reinstalling miner on respawn",
                "cpu_share": 0.10,
            },
        ),
    ),
                                                                        
                                                                
                                            
    "insider": AttackSpec(
        kind="insider",
        primary_system=DATABASE,
        cpu_boost=(14.0, 28.0),
        rps_multiplier=(1.2, 2.0),
        latency_multiplier=(1.6, 3.2),
        error_rate_range=(0.8, 1.6),
        anomalies=("unusual_data_access", "abnormal_db_queries"),
        rogue_processes=(
            {
                "name": "data_exfiltrator.py",
                "role": "foreign · exfil",
                "summary": "Bulk SELECT bypassing app-layer rate limit, exfil to external IP",
                "cpu_share": 0.20,
            },
            {
                "name": "priv_escalator.sh",
                "role": "foreign · privilege",
                "summary": "sudo invocation chain attempting role grant on accounts schema",
                "cpu_share": 0.10,
            },
        ),
    ),
}

ATTACK_TYPES: tuple[str, ...] = tuple(_ATTACKS.keys())


def attack_spec(kind: str) -> AttackSpec:
    try:
        return _ATTACKS[kind]
    except KeyError as exc:
        valid = ", ".join(sorted(_ATTACKS))
        raise KeyError(f"Unknown attack {kind!r}. Valid: {valid}") from exc


                                                                              


@dataclass
class _AttackState:
    """Active engagement on one system."""

    spec: AttackSpec
    triggered_at: float
    expires_at: float
    intensity: float = 1.0                                             


@dataclass
class SystemState:
    """Mutable runtime state for one banking system."""

    spec: SystemSpec
    started_at: float = field(default_factory=time.time)
    seed: float = field(default_factory=lambda: random.uniform(0.0, math.tau))
    attack: Optional[_AttackState] = None
    lateral_until: float = 0.0                                               


                                                                              

EmitFn = Callable[[dict[str, Any]], Awaitable[None]]
"""Callable that ships one frame to subscribers. Made injectable so the
simulator stays decoupled from any specific transport (testable in
isolation; production wires it to ``ConnectionManager.broadcast_text``)."""


async def _noop_emitter(_frame: dict[str, Any]) -> None:
    return None


                                                                              


class BankingSimulator:
    """Async banking infrastructure simulator.

    Lifecycle: ``start()`` schedules a background task that ticks every
    ``interval_seconds``. ``stop()`` cooperatively cancels it.

    Each tick:
      * advances internal sine-wobble timers
      * recomputes per-system snapshot (status, CPU, RPS, processes)
      * emits one ``system_update`` frame per system through ``emit``
    """

    def __init__(
        self,
        *,
        emit: EmitFn = _noop_emitter,
        interval_seconds: float = 1.5,
        attack_duration_seconds: float = 14.0,
        lateral_extra_seconds: float = 4.0,
        is_subscriber_present: Optional[Callable[[], bool]] = None,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        if attack_duration_seconds <= 0:
            raise ValueError("attack_duration_seconds must be > 0")

        self._emit = emit
        self._interval = interval_seconds
        self._attack_duration = attack_duration_seconds
        self._lateral_extra = lateral_extra_seconds
        self._is_subscriber_present = is_subscriber_present or (lambda: True)

        self._states: dict[str, SystemState] = {
            sid: SystemState(spec=spec) for sid, spec in SPECS.items()
        }
        self._lock = asyncio.Lock()
        self._task: Optional[asyncio.Task[None]] = None
        self._stopping = asyncio.Event()
        self._tick_count = 0

                                                                             

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        """Schedule the background tick task. Idempotent."""
        if self.running:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(
            self._run(), name="banking-simulator"
        )
        logger.info(
            "banking simulator started (interval=%.2fs, duration=%.1fs)",
            self._interval,
            self._attack_duration,
        )

    async def stop(self) -> None:
        """Cooperatively cancel the background task."""
        self._stopping.set()
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        finally:
            self._task = None
        logger.info("banking simulator stopped")

                                                                             

    async def inject_attack(
        self,
        attack_type: str,
        *,
        target_system: Optional[str] = None,
        duration_seconds: Optional[float] = None,
    ) -> dict[str, Any]:
        """Lift a system into attack mode and emit an immediate snapshot.

        Args:
            attack_type: One of :data:`ATTACK_TYPES`.
            target_system: Override the spec's default primary (useful for
                ``crypto_miner`` which can hit any host).
            duration_seconds: Override the configured engagement length.

        Returns:
            A summary dict — ``{system, attack_type, expires_at, peer}``.
        """
        spec = attack_spec(attack_type)
        sys_id = target_system or spec.primary_system
        if sys_id not in self._states:
            valid = ", ".join(SYSTEMS)
            raise KeyError(f"Unknown system {sys_id!r}. Valid: {valid}")

        duration = float(duration_seconds or self._attack_duration)
        now = time.time()
        expires_at = now + duration

        async with self._lock:
            state = self._states[sys_id]
            state.attack = _AttackState(
                spec=spec,
                triggered_at=now,
                expires_at=expires_at,
            )
                                              
            peer_state = self._states[state.spec.cluster_peer]
            peer_state.lateral_until = max(
                peer_state.lateral_until,
                expires_at + self._lateral_extra,
            )
            peer_id = peer_state.spec.id

        logger.info(
            "banking attack injected: kind=%s system=%s peer=%s for %.1fs",
            attack_type,
            sys_id,
            peer_id,
            duration,
        )

                                                                        
                                                                 
        await self._emit_system(sys_id)
        await self._emit_system(peer_id)

        return {
            "system": sys_id,
            "attack_type": attack_type,
            "duration_seconds": duration,
            "expires_at": _iso(expires_at),
            "peer_system": peer_id,
        }

    async def clear_attacks(self) -> None:
        """Force every system back to normal immediately."""
        async with self._lock:
            for state in self._states.values():
                state.attack = None
                state.lateral_until = 0.0
        logger.info("banking simulator: all attacks cleared")

    async def snapshot(self) -> list[dict[str, Any]]:
        """Return one ``system_update`` frame per system without emitting."""
        async with self._lock:
            return [self._build_frame(sid) for sid in SYSTEMS]

                                                                             

    async def _run(self) -> None:
        try:
            while not self._stopping.is_set():
                try:
                    await self._tick()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("banking simulator tick failed")

                try:
                    await asyncio.wait_for(
                        self._stopping.wait(), timeout=self._interval
                    )
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            return

    async def _tick(self) -> None:
        self._tick_count += 1

                                                                        
                                                                  
        await self._expire_finished_attacks()
        if not self._is_subscriber_present():
            return

        for sys_id in SYSTEMS:
            await self._emit_system(sys_id)

    async def _expire_finished_attacks(self) -> None:
        now = time.time()
        async with self._lock:
            for state in self._states.values():
                if state.attack and state.attack.expires_at <= now:
                    state.attack = None
                if state.lateral_until and state.lateral_until <= now:
                    state.lateral_until = 0.0

    async def _emit_system(self, sys_id: str) -> None:
        async with self._lock:
            frame = self._build_frame(sys_id)
        try:
            await self._emit(frame)
        except Exception:
            logger.exception(
                "banking simulator: emit failed for %s", sys_id
            )

                                                                            

    def _build_frame(self, sys_id: str) -> dict[str, Any]:
        state = self._states[sys_id]
        spec = state.spec
        now = time.time()

                                                                          
        t = self._tick_count
        wobble = (
            math.sin(t * 0.55 + state.seed) * 0.08
            + math.cos(t * 0.21 + state.seed * 1.7) * 0.05
        )

                                                                         
        attack = state.attack
        intensity = _attack_envelope(attack, now) if attack else 0.0
        is_under_attack = intensity > 0.05

        is_lateral = (not is_under_attack) and now < state.lateral_until

        cpu, rps, latency_ms, error_rate, anomalies = _baseline_metrics(
            spec, wobble
        )

        if is_under_attack:
            cpu_extra = _between(*attack.spec.cpu_boost) * intensity
            rps_mult = _between(*attack.spec.rps_multiplier)
            lat_mult = _between(*attack.spec.latency_multiplier)
            err_floor = _between(*attack.spec.error_rate_range)

            cpu = min(98.0, cpu + cpu_extra)
            rps = int(rps * (1.0 + (rps_mult - 1.0) * intensity))
            latency_ms = int(latency_ms * (1.0 + (lat_mult - 1.0) * intensity))
            error_rate = round(err_floor * intensity, 2)
            anomalies = list(attack.spec.anomalies)
        elif is_lateral:
            cpu = min(85.0, cpu + 18.0 + abs(wobble) * 6.0)
            latency_ms = int(latency_ms * 1.6)
            error_rate = round(0.6 + abs(wobble) * 0.5, 2)
            anomalies = ["lateral_pressure"]

        status = _status_from_metrics(cpu, error_rate, is_under_attack)
                                                                         
                                                                        
                                                                 
        if is_lateral and status == "normal":
            status = "warning"

        processes = _build_process_list(
            spec=spec,
            system_cpu=cpu,
            attack=attack if is_under_attack else None,
        )

        return {
            "type": "system_update",
            "system": sys_id,
            "data": {
                "name": spec.display_name,
                "cpu": round(cpu, 1),
                "requests": int(rps),
                "latency_ms": int(latency_ms),
                "error_rate": float(error_rate),
                "status": status,
                "uptime_s": int(now - state.started_at),
                "anomalies": anomalies,
                "processes": processes,
                "attack": (
                    {
                        "kind": attack.spec.kind,
                        "expires_at": _iso(attack.expires_at),
                        "intensity": round(intensity, 2),
                    }
                    if is_under_attack
                    else None
                ),
                "ts": _iso(now),
            },
        }


                                                                              


def _baseline_metrics(
    spec: SystemSpec, wobble: float
) -> tuple[float, int, int, float, list[str]]:
    cpu = max(2.0, spec.base_cpu * (1.0 + wobble))
    rps = max(1, int(spec.base_rps * (1.0 + wobble)))
    latency = max(1, int(spec.base_latency_ms * (1.0 + abs(wobble) * 0.4)))
    error_rate = round(max(0.0, 0.02 + wobble * 0.04), 3)
    return cpu, rps, latency, error_rate, []


def _status_from_metrics(cpu: float, err: float, under_attack: bool) -> str:
    if under_attack and (cpu >= 75.0 or err >= 1.5):
        return "critical"
    if under_attack:
        return "warning"
    if cpu >= 80.0 or err >= 1.5:
        return "critical"
    if cpu >= 60.0 or err >= 0.6:
        return "warning"
    return "normal"


def _attack_envelope(attack: _AttackState, now: float) -> float:
    """Triangular 0→1→0 envelope across the engagement window."""
    span = max(0.001, attack.expires_at - attack.triggered_at)
    progress = (now - attack.triggered_at) / span
    if progress <= 0.0 or progress >= 1.0:
        return 0.0
                                                               
    if progress < 0.25:
        return progress / 0.25
    if progress > 0.75:
        return max(0.0, (1.0 - progress) / 0.25)
    return 1.0


def _build_process_list(
    *,
    spec: SystemSpec,
    system_cpu: float,
    attack: Optional[_AttackState],
) -> list[dict[str, Any]]:
    """Distribute system CPU across legitimate + injected rogue processes."""
    base = list(spec.base_processes)
    rogues = list(attack.spec.rogue_processes) if attack else []
    rogue_share = sum(p.get("cpu_share", 0.0) for p in rogues)
    legit_share = max(0.0, 1.0 - rogue_share)

    out: list[dict[str, Any]] = []
                                                                       
                                                                  
    weights = [1.0 + (i * 0.07) for i, _ in enumerate(base)]
    weight_sum = sum(weights) or 1.0
    legit_cpu_total = system_cpu * legit_share

    for i, proc in enumerate(base):
        share = weights[i] / weight_sum
        proc_cpu = round(legit_cpu_total * share, 2)
        out.append(
            {
                "name": proc["name"],
                "pid": proc["pid"],
                "role": proc["role"],
                "cpu": proc_cpu,
                "status": "ok",
                "malicious": False,
            }
        )

                                                                         
                                                                   
                
    for proc in rogues:
        out.append(
            {
                "name": proc["name"],
                "pid": random.randint(31000, 64999),
                "role": proc.get("role", "foreign"),
                "cpu": round(system_cpu * float(proc.get("cpu_share", 0.2)), 2),
                "status": "malicious",
                "malicious": True,
                "summary": proc.get("summary"),
            }
        )

    return out


def _iso(epoch: float) -> str:
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _between(lo: float, hi: float) -> float:
    if hi <= lo:
        return lo
    return random.uniform(lo, hi)


                                                                             

_simulator: Optional[BankingSimulator] = None


def init_banking_simulator(
    *,
    emit: EmitFn,
    interval_seconds: float = 1.5,
    attack_duration_seconds: float = 14.0,
    is_subscriber_present: Optional[Callable[[], bool]] = None,
) -> BankingSimulator:
    """Install a fresh :class:`BankingSimulator` as the active instance.

    Always constructs a new instance so its asyncio primitives bind to
    the current event loop. Important for repeated lifespan starts (e.g.
    test suites that spin up multiple ``TestClient`` sessions in one
    process).
    """
    global _simulator
    _simulator = BankingSimulator(
        emit=emit,
        interval_seconds=interval_seconds,
        attack_duration_seconds=attack_duration_seconds,
        is_subscriber_present=is_subscriber_present,
    )
    return _simulator


def get_banking_simulator() -> BankingSimulator:
    """Return the active simulator — raises if not yet initialized."""
    if _simulator is None:
        raise RuntimeError(
            "BankingSimulator has not been initialized. "
            "Call init_banking_simulator(...) during application startup."
        )
    return _simulator


def _reset_for_tests() -> None:
    """Drop the active instance — used by tests to fully reset state."""
    global _simulator
    _simulator = None


                                                                             


def make_websocket_emitter(manager: Any) -> EmitFn:
    """Build an :data:`EmitFn` that JSON-encodes frames and broadcasts.

    Decoupled from :mod:`app.services.websocket` to avoid an import cycle
    — the manager is duck-typed (``async broadcast_text(text: str)``).
    """

    async def _emit(frame: dict[str, Any]) -> None:
        await manager.broadcast_text(json.dumps(frame, default=str))

    return _emit
