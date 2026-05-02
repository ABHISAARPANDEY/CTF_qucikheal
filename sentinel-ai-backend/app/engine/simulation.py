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
    )


SIMULATORS: dict[str, Callable[[], Event]] = {
    "ddos": generate_ddos_event,
    "brute_force": generate_bruteforce_event,
    "sql_injection": generate_sql_injection_event,
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
