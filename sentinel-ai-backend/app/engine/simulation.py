"""Synthetic attack-event generator for SentinelAI.

Produces realistic-looking :class:`app.models.event.Event` instances for
development, demos, load testing, and detection-engine evaluation. Pure
stdlib — no external dependencies.

Add a new attack type by:
    1. Writing a ``generate_<name>_event()`` function that returns ``Event``.
    2. Registering it in :data:`SIMULATORS`.
"""

from __future__ import annotations

import random
from typing import Callable, Sequence, TypeVar

from app.models.event import Event, EventType, Severity

T = TypeVar("T")


_PUBLIC_FIRST_OCTETS: tuple[int, ...] = (
    4, 8, 11, 23, 38, 45, 51, 66, 77, 89,
    101, 123, 142, 156, 178, 185, 193, 200, 203, 212,
)

_COMMON_TARGET_USERS: tuple[str, ...] = (
    "root", "admin", "administrator", "ubuntu", "ec2-user",
    "postgres", "mysql", "oracle", "git", "test", "user", "dev",
)

_SQLI_PAYLOADS: tuple[str, ...] = (
    "' OR '1'='1",
    "' OR '1'='1' --",
    "admin' --",
    "' UNION SELECT NULL,username,password FROM users --",
    "'; DROP TABLE users; --",
    "1 OR 1=1",
    "' OR 'a'='a",
    "1' AND SLEEP(5) --",
    "%27%20OR%201%3D1--",
)

_SQLI_ENDPOINTS: tuple[str, ...] = (
    "/api/login", "/api/users", "/api/products", "/api/search",
    "/login.php", "/index.php", "/search", "/admin", "/account",
)

_DDOS_TARGET_PORTS: tuple[int, ...] = (53, 80, 123, 443, 8080, 8443)

_BRUTEFORCE_PROTOCOLS: tuple[tuple[str, int], ...] = (
    ("SSH", 22),
    ("RDP", 3389),
    ("FTP", 21),
    ("SMTP", 25),
    ("MySQL", 3306),
    ("PostgreSQL", 5432),
)


def _weighted_choice(choices: Sequence[tuple[T, float]]) -> T:
    """Pick one item from ``[(value, weight), ...]`` proportional to weight."""
    values, weights = zip(*choices)
    return random.choices(values, weights=weights, k=1)[0]


def _random_public_ip() -> str:
    """Generate a plausible public IPv4 address (skips private/reserved blocks)."""
    return (
        f"{random.choice(_PUBLIC_FIRST_OCTETS)}."
        f"{random.randint(0, 255)}."
        f"{random.randint(0, 255)}."
        f"{random.randint(1, 254)}"
    )


def generate_ddos_event() -> Event:
    """Return a synthetic DDoS event (volumetric flood)."""
    pattern = random.choice(("SYN flood", "UDP amplification", "HTTP flood", "DNS amplification"))
    port = random.choice(_DDOS_TARGET_PORTS)
    pps = random.randint(50_000, 2_000_000)
    gbps = round(random.uniform(1.5, 120.0), 1)
    sources = random.randint(500, 50_000)

    message = (
        f"{pattern} detected: {pps:,} packets/sec ({gbps} Gbps) "
        f"from ~{sources:,} sources targeting port {port}"
    )

    severity = _weighted_choice([
        (Severity.HIGH, 0.6),
        (Severity.CRITICAL, 0.4),
    ])

    return Event(
        source_ip=_random_public_ip(),
        event_type=EventType.NETWORK,
        severity=severity,
        message=message,
        label="ddos",
    )


def generate_bruteforce_event() -> Event:
    """Return a synthetic brute-force authentication event."""
    protocol, port = random.choice(_BRUTEFORCE_PROTOCOLS)
    user = random.choice(_COMMON_TARGET_USERS)
    attempts = random.randint(5, 500)
    window_seconds = random.choice((10, 30, 60, 120, 300))

    message = (
        f"{protocol} brute-force: {attempts} failed login attempts "
        f"as '{user}' on port {port} within {window_seconds}s"
    )

    severity = _weighted_choice([
        (Severity.LOW, 0.25),
        (Severity.MEDIUM, 0.45),
        (Severity.HIGH, 0.25),
        (Severity.CRITICAL, 0.05),
    ])

    return Event(
        source_ip=_random_public_ip(),
        event_type=EventType.AUTH,
        severity=severity,
        message=message,
        label="brute_force",
    )


def generate_sql_injection_event() -> Event:
    """Return a synthetic SQL-injection attempt against a web endpoint."""
    payload = random.choice(_SQLI_PAYLOADS)
    endpoint = random.choice(_SQLI_ENDPOINTS)
    method = random.choice(("GET", "POST"))
    param = random.choice(("id", "user", "q", "search", "name", "email"))

    message = (
        f"SQLi pattern detected on {method} {endpoint} "
        f"({param}={payload!r})"
    )

    severity = _weighted_choice([
        (Severity.MEDIUM, 0.3),
        (Severity.HIGH, 0.5),
        (Severity.CRITICAL, 0.2),
    ])

    return Event(
        source_ip=_random_public_ip(),
        event_type=EventType.INTRUSION,
        severity=severity,
        message=message,
        label="sql_injection",
    )


_UA_POOL: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
    "NeoBank-iOS/5.12.0 (iPhone15,3; iOS 17.4)",
    "NeoBank-Android/5.12.0 (Pixel 8; Android 14)",
)
_BOT_UA_POOL: tuple[str, ...] = (
    "python-requests/2.31.0",
    "python-urllib3/2.2.1",
    "okhttp/4.9.3",
    "Go-http-client/1.1",
    "curl/8.4.0",
)
_BENIGN_ENDPOINTS: tuple[tuple[str, float], ...] = (
    ("/api/login", 0.18), ("/api/accounts", 0.22), ("/api/transactions", 0.25),
    ("/api/transfer", 0.12), ("/api/cards", 0.08), ("/health", 0.10), ("/api/profile", 0.05),
)
_FIRST_NAMES = ("alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy",
                "mallory", "niaj", "olivia", "peggy", "rupert", "sybil", "trent", "victor", "wendy")
_LAST_NAMES = ("smith", "patel", "garcia", "nguyen", "okafor", "kim", "rossi", "silva", "mueller", "chen")
_GEOS = ("US", "GB", "IN", "DE", "BR", "SG", "CA", "AU")

# A stable population of legitimate customers (ip, user, ua, geo) so per-entity
# baselines have real repeat traffic to learn from.
_rng_pop = random.Random(1234)
_CUSTOMERS: tuple[dict, ...] = tuple(
    {
        "ip": f"{_rng_pop.choice(_PUBLIC_FIRST_OCTETS)}.{_rng_pop.randint(0, 255)}.{_rng_pop.randint(0, 255)}.{_rng_pop.randint(1, 254)}",
        "user": f"{_rng_pop.choice(_FIRST_NAMES)}.{_rng_pop.choice(_LAST_NAMES)}{_rng_pop.randint(1, 99)}@neobank.io",
        "ua": _rng_pop.choice(_UA_POOL),
        "geo": _rng_pop.choice(_GEOS),
    }
    for _ in range(400)
)


def _random_public_ip_r(r: random.Random) -> str:
    return f"{r.choice(_PUBLIC_FIRST_OCTETS)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"


def generate_benign_event(rng: random.Random | None = None) -> Event:
    """A normal customer interaction. Occasionally a single mistyped password."""
    r = rng or random
    c = r.choice(_CUSTOMERS)
    endpoint = _weighted_choice(_BENIGN_ENDPOINTS) if rng is None else _weighted_choice_r(r, _BENIGN_ENDPOINTS)
    status = 200
    if endpoint == "/api/login" and r.random() < 0.06:
        status = 401
    method = "POST" if endpoint in ("/api/login", "/api/transfer") else "GET"
    return Event(
        source_ip=c["ip"],
        event_type=EventType.AUTH if endpoint == "/api/login" else EventType.SYSTEM,
        severity=Severity.INFO,
        message=f"{method} {endpoint} user={c['user']} status={status} ua={c['ua'][:24]}",
        username=c["user"],
        dest_port=443,
        user_agent=c["ua"],
        status_code=status,
        endpoint=endpoint,
        geo=c["geo"],
        label="benign",
    )


def _weighted_choice_r(r: random.Random, choices: Sequence[tuple[T, float]]) -> T:
    values, weights = zip(*choices)
    return r.choices(values, weights=weights, k=1)[0]


SESSION_KINDS: frozenset[str] = frozenset({
    "benign", "port_scan", "credential_stuffing", "low_slow_brute_force",
    "brute_force", "ddos", "sql_injection",
})


class AttackSession:
    """Stateful multi-event campaign generator.

    ``next()`` returns the next event of the campaign; ``delay_hint()`` is
    the natural spacing in seconds (the traffic generator divides this by a
    ``speed`` factor so a 30-second cadence can play out in 3 seconds for a
    demo).
    """

    def __init__(self, kind: str, *, seed: int | None = None) -> None:
        if kind not in SESSION_KINDS:
            raise KeyError(f"Unknown session kind {kind!r}. Valid: {sorted(SESSION_KINDS)}")
        self.kind = kind
        self.r = random.Random(seed)
        self.n = 0
        self._ip = _random_public_ip_r(self.r)
        self._port_cursor = self.r.randint(1, 1000)
        self._sequential = self.r.random() < 0.6
        self._bot_ua = self.r.choice(_BOT_UA_POOL)
        self._pool_subnets = [
            f"{self.r.choice(_PUBLIC_FIRST_OCTETS)}.{self.r.randint(0, 255)}.{self.r.randint(0, 255)}"
            for _ in range(8)
        ]
        self._target_user = f"{self.r.choice(_FIRST_NAMES)}.{self.r.choice(_LAST_NAMES)}@neobank.io"
        self._endpoint = self.r.choice(("/oauth/token", "/api/login"))

    # -- kinds ----------------------------------------------------------

    def _port_scan(self) -> Event:
        if self._sequential:
            port = self._port_cursor
            self._port_cursor += 1
        else:
            port = self.r.randint(1, 65535)
        sport = self.r.randint(32768, 60999)
        return Event(
            source_ip=self._ip,
            event_type=EventType.NETWORK,
            severity=Severity.INFO,
            message=f"SYN {self._ip}:{sport} -> 10.0.0.12:{port} flags=S",
            dest_port=port,
            label="port_scan",
        )

    def _credential_stuffing(self) -> Event:
        subnet = self.r.choice(self._pool_subnets)
        ip = f"{subnet}.{self.r.randint(1, 254)}"
        user = f"{self.r.choice(_FIRST_NAMES)}.{self.r.choice(_LAST_NAMES)}{self.r.randint(1, 9999)}@gmail.com"
        return Event(
            source_ip=ip,
            event_type=EventType.AUTH,
            severity=Severity.LOW,
            message=f"POST {self._endpoint} user={user} status=401 ua={self._bot_ua}",
            username=user,
            dest_port=443,
            user_agent=self._bot_ua,
            status_code=401,
            endpoint=self._endpoint,
            label="credential_stuffing",
        )

    def _low_slow(self) -> Event:
        ip = _random_public_ip_r(self.r)
        ua = self.r.choice(_UA_POOL)
        return Event(
            source_ip=ip,
            event_type=EventType.AUTH,
            severity=Severity.LOW,
            message=f"POST /api/login user={self._target_user} status=401 ua={ua[:24]}",
            username=self._target_user,
            dest_port=443,
            user_agent=ua,
            status_code=401,
            endpoint="/api/login",
            label="low_slow_brute_force",
        )

    def _legacy(self) -> Event:
        e = SIMULATORS[self.kind]()
        return e.model_copy(update={"label": self.kind})

    def next(self) -> Event:
        self.n += 1
        if self.kind == "port_scan":
            return self._port_scan()
        if self.kind == "credential_stuffing":
            return self._credential_stuffing()
        if self.kind == "low_slow_brute_force":
            return self._low_slow()
        if self.kind == "benign":
            return generate_benign_event(self.r)
        return self._legacy()

    def delay_hint(self) -> float:
        return {
            "port_scan": 0.15,
            "credential_stuffing": 0.4,
            "low_slow_brute_force": 30.0,
            "brute_force": 1.0,
            "ddos": 0.1,
            "sql_injection": 1.5,
            "benign": 0.5,
        }[self.kind]


SIMULATORS: dict[str, Callable[[], Event]] = {
    "ddos": generate_ddos_event,
    "brute_force": generate_bruteforce_event,
    "sql_injection": generate_sql_injection_event,
    "benign": generate_benign_event,
    "port_scan": lambda: AttackSession("port_scan").next(),
    "credential_stuffing": lambda: AttackSession("credential_stuffing").next(),
    "low_slow_brute_force": lambda: AttackSession("low_slow_brute_force").next(),
}


def generate_event(attack_type: str | None = None) -> Event:
    """Generate one event of the given type, or a random type if ``None``.

    Raises:
        KeyError: if ``attack_type`` is provided but not registered.
    """
    if attack_type is None:
        generator = random.choice(list(SIMULATORS.values()))
    else:
        try:
            generator = SIMULATORS[attack_type]
        except KeyError as exc:
            valid = ", ".join(sorted(SIMULATORS))
            raise KeyError(
                f"Unknown attack_type {attack_type!r}. Valid: {valid}"
            ) from exc
    return generator()


def generate_batch(n: int, attack_type: str | None = None) -> list[Event]:
    """Generate ``n`` events. If ``attack_type`` is None each event is random."""
    if n < 0:
        raise ValueError("n must be non-negative")
    return [generate_event(attack_type) for _ in range(n)]


def benign_feature_matrix(*, n: int = 2000, seed: int = 42):
    """Synthetic benign FeatureVectors for scorer warm-up.

    Generates ``n`` benign events on a simulated clock and pushes them
    through a scratch :class:`FeatureStore`, so the resulting vectors have
    exactly the shape real traffic produces — including cold-start vectors
    for entities seen once. Returns ``(X, per_type)``: an ``n × len(FIELDS)``
    numpy array of IP-view vectors, and per-entity-type vector lists for
    baseline seeding.
    """
    from datetime import datetime, timedelta, timezone

    import numpy as np

    from app.engine.features import FeatureStore, FeatureVector

    rng = random.Random(seed)
    store = FeatureStore()
    per_type: dict[str, list[FeatureVector]] = {"ip": [], "user": [], "subnet": []}
    rows: list[list[float]] = []
    clock = datetime.now(timezone.utc) - timedelta(seconds=n * 0.08)
    for _ in range(n):
        clock += timedelta(seconds=rng.uniform(0.02, 0.15))
        ev = generate_benign_event(rng).model_copy(update={"timestamp": clock})
        vectors = store.observe(ev)
        for etype, fv in vectors.items():
            per_type[etype].append(fv)
        rows.append(vectors["ip"].as_list())
    return np.asarray(rows, dtype=float), per_type
