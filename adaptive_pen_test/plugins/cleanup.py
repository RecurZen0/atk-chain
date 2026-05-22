from __future__ import annotations

from typing import Any, Dict

from adaptive_pen_test.plugin_manager import BasePlugin


class CleanupPlugin(BasePlugin):
    """Register cleanup tasks for artifacts created during an attack."""

    async def run(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        file_path = params.get("file_path")
        shell_command = params.get("shell_command", f"rm -f {file_path}")
        if file_path:
            context.setdefault("artifacts", []).append(file_path)
        context.setdefault("cleanup_tasks", []).append({"file_path": file_path, "shell_command": shell_command})
        return {"registered": file_path, "command": shell_command}
