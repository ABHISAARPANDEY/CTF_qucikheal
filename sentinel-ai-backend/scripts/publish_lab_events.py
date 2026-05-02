from __future__ import annotations

import asyncio
import json
import random
from datetime import datetime, timezone

from aiokafka import AIOKafkaProducer


TOPIC = "raw.events"
BOOTSTRAP = "redpanda:9092"

JUICE_PATHS = [
    "/rest/products/search?q=' OR '1'='1",
    "/rest/user/login",
    "/rest/basket/1/checkout",
    "/ftp/package.json.bak",
    "/rest/admin/application-configuration",
]

USER_AGENTS = [
    "sqlmap/1.8.4#stable",
    "Mozilla/5.0",
    "python-requests/2.32",
    "curl/8.7.1",
]


def _event() -> dict:
    path = random.choice(JUICE_PATHS)
    msg = f"JuiceShop traffic method=GET path={path} status={random.choice([200, 401, 403, 500])}"
    if "OR" in path:
        msg = f"Potential SQLi probe path={path}"
    if "login" in path:
        msg = "Repeated failed login attempts observed on Juice Shop auth endpoint"
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": f"198.51.100.{random.randint(10, 250)}",
        "event_type": random.choice(["intrusion", "auth", "network"]),
        "severity": random.choice(["low", "medium", "high"]),
        "method": "GET",
        "path": path,
        "status": random.choice([200, 401, 429, 500]),
        "user_agent": random.choice(USER_AGENTS),
        "message": msg,
    }


async def main() -> None:
    producer = AIOKafkaProducer(
        bootstrap_servers=BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    await producer.start()
    try:
        while True:
            await producer.send_and_wait(TOPIC, _event())
            await asyncio.sleep(1.5)
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
