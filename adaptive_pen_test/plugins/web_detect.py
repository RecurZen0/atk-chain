from __future__ import annotations

import asyncio
from typing import Any, Dict

import requests

from adaptive_pen_test.plugin_manager import BasePlugin


class WebDetectPlugin(BasePlugin):
    """Perform simple web detection against a target URL."""

    async def run(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url")
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(None, lambda: requests.get(url, timeout=5))
        server = response.headers.get("Server", "unknown")
        title = self._extract_title(response.text)
        context["web_server"] = {"banner": server, "title": title}
        return {"status_code": response.status_code, "banner": server, "title": title}

    @staticmethod
    def _extract_title(html: str) -> str:
        start = html.lower().find("<title>")
        end = html.lower().find("</title>")
        if start != -1 and end != -1:
            return html[start + 7 : end].strip()
        return ""
