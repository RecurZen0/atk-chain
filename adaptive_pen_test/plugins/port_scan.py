from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, List

from adaptive_pen_test.plugin_manager import BasePlugin


class PortScanPlugin(BasePlugin):
    """Scan TCP ports and store open ports in the shared context."""

    async def run(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        ports = params.get("ports", [])
        target_ip = context.get("target", {}).get("ip")
        open_ports: List[int] = []

        async def _probe(port: int) -> None:
            loop = asyncio.get_running_loop()
            try:
                await loop.run_in_executor(None, self._check_port, target_ip, port)
                open_ports.append(port)
            except OSError:
                pass

        await asyncio.gather(*[_probe(port) for port in ports])
        context["open_ports"] = open_ports
        return {"open_ports": open_ports}

    @staticmethod
    def _check_port(target_ip: str, port: int) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.5)
            sock.connect((target_ip, port))
