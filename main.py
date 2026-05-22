from __future__ import annotations

import argparse
import asyncio
import logging

from adaptive_pen_test.engine import AttackEngine
from adaptive_pen_test.event_state import EventType


async def main() -> None:
    parser = argparse.ArgumentParser(description="Adaptive penetration testing engine")
    parser.add_argument("--config", default="adaptive_pen_test/configs/level1.1.yaml", help="Attack chain YAML path")
    parser.add_argument("--target-ip", default="192.168.1.100", help="Target IP address")
    parser.add_argument("--attacker-ip", default="10.0.0.1", help="Attacker IP address")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    engine = AttackEngine(args.config, target_ip=args.target_ip, attacker_ip=args.attacker_ip)
    engine.trigger_event(EventType.START)
    await engine.run()


if __name__ == "__main__":
    asyncio.run(main())
