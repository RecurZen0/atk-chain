from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


class EvidenceLogger:
    """Collect forensic evidence during the attack execution."""

    def __init__(self) -> None:
        self.entries: List[Dict[str, Any]] = []

    def log_step(self, step_id: str, request: Dict[str, Any], response: Dict[str, Any], command_output: str | None = None) -> None:
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "step_id": step_id,
            "request": request,
            "response": response,
            "command_output": command_output,
        }
        self.entries.append(entry)

    def save_report(self, output_dir: str) -> None:
        os.makedirs(output_dir, exist_ok=True)
        output_path = Path(output_dir) / "evidence_report.json"
        with output_path.open("w", encoding="utf-8") as stream:
            json.dump({"generated_at": datetime.utcnow().isoformat() + "Z", "entries": self.entries}, stream, indent=2)
        html_path = Path(output_dir) / "evidence_report.html"
        with html_path.open("w", encoding="utf-8") as stream:
            stream.write("<html><head><title>Evidence Report</title></head><body>\n")
            stream.write(f"<h1>Evidence Report</h1><p>Generated: {datetime.utcnow().isoformat()}Z</p>\n")
            for entry in self.entries:
                stream.write(f"<h2>{entry['step_id']}</h2>\n")
                stream.write(f"<pre>{json.dumps(entry, indent=2)}</pre>\n")
            stream.write("</body></html>\n")


class CleanupManager:
    """Register cleanup artifacts and execute removal commands."""

    def __init__(self) -> None:
        self.artifacts: List[Dict[str, Any]] = []

    def register_artifact(self, file_path: str, shell_command: str) -> None:
        self.artifacts.append({"file_path": file_path, "shell_command": shell_command})

    async def cleanup(self, context: Dict[str, Any]) -> None:
        import asyncio
        import shlex
        import subprocess

        for artifact in self.artifacts:
            path = artifact["file_path"]
            command = artifact["shell_command"]
            if os.path.exists(path):
                try:
                    proc = await asyncio.create_subprocess_shell(
                        command,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await proc.communicate()
                    context.setdefault("cleanup", []).append({"artifact": path, "stdout": stdout.decode(errors="ignore"), "stderr": stderr.decode(errors="ignore")})
                except Exception as exc:
                    context.setdefault("cleanup_errors", []).append(str(exc))
