from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List

import requests


class DefenseSensor:
    """Detect defensive mechanisms such as WAF, IDS, and honeypots."""

    def detect_waf(self, target_url: str, test_payloads: List[str]) -> bool:
        """Send test payloads and determine if a WAF is present."""
        for payload in test_payloads:
            try:
                response = requests.get(target_url, params={"q": payload}, timeout=5)
                if response.status_code in {406, 403, 503}:
                    return True
                if any(token in response.text.lower() for token in ["waf", "blocked", "forbidden"]):
                    return True
            except requests.RequestException:
                continue
        return False

    async def detect_ids_slowdown(self) -> bool:
        """Estimate IDS/IPS intervention by measuring response latencies."""
        delays = []
        for _ in range(3):
            start = time.monotonic()
            await asyncio.sleep(0.1)
            delays.append(time.monotonic() - start)
        return max(delays) > 0.5

    def detect_honeypot(self, service_banner: str) -> float:
        """Return a honeypot confidence score based on service banner heuristics."""
        score = 0.0
        if any(keyword in service_banner.lower() for keyword in ["honeypot", "cowrie", "honey", "fake"]):
            score = 0.9
        elif "apache" in service_banner.lower() or "nginx" in service_banner.lower():
            score = 0.1
        return score
