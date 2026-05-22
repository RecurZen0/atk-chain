from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from adaptive_pen_test.ai_strategy import AIStrategy
from adaptive_pen_test.config_loader import flatten_attack_chain, load_attack_chain
from adaptive_pen_test.defense_sensor import DefenseSensor
from adaptive_pen_test.event_state import AttackState, EventType, StateMachine
from adaptive_pen_test.forensics import CleanupManager, EvidenceLogger
from adaptive_pen_test.plugin_manager import PluginManager

logger = logging.getLogger(__name__)


class AttackEngine:
    """Event-driven attack engine that dispatches stages and plugins."""

    def __init__(self, config_path: str, target_ip: str, attacker_ip: str) -> None:
        self.config_path = config_path
        self.target_ip = target_ip
        self.attacker_ip = attacker_ip
        self.queue: asyncio.Queue = asyncio.Queue()
        self.state_machine = StateMachine()
        self.context: Dict[str, Any] = {
            "target": {"ip": target_ip, "port": None},
            "attacker": {"ip": attacker_ip},
            "open_ports": [],
            "web_server": {},
            "session_cookie": None,
            "low_shell": None,
            "root_shell": None,
            "credentials": [],
            "defense": {"waf": False, "honeypot_prob": 0.0},
            "evidence_log": [],
        }
        self.config = load_attack_chain(config_path)
        self.attack_chain: List[Dict[str, Any]] = []
        self.ai_strategy = AIStrategy("ai_rules.yaml")
        self.plugin_manager = PluginManager()
        self.sensor = DefenseSensor()
        self.evidence = EvidenceLogger()
        self.cleanup_manager = CleanupManager()
        self.history_events: List[Dict[str, Any]] = []
        self._register_builtin_plugins()
        self._initialize_chain()

    def _register_builtin_plugins(self) -> None:
        from adaptive_pen_test.plugins.port_scan import PortScanPlugin
        from adaptive_pen_test.plugins.web_detect import WebDetectPlugin
        from adaptive_pen_test.plugins.sqli_login_bypass import SqliLoginBypassPlugin
        from adaptive_pen_test.plugins.cmd_inject import CmdInjectPlugin
        from adaptive_pen_test.plugins.reverse_shell_handler import ReverseShellHandler
        from adaptive_pen_test.plugins.kernel_privesc import KernelPrivescPlugin
        from adaptive_pen_test.plugins.udf_privesc import UdfPrivescPlugin
        from adaptive_pen_test.plugins.lfi import LfiPlugin
        from adaptive_pen_test.plugins.cleanup import CleanupPlugin

        self.plugin_manager.register_plugin("PortScanPlugin", PortScanPlugin)
        self.plugin_manager.register_plugin("WebDetectPlugin", WebDetectPlugin)
        self.plugin_manager.register_plugin("SqliLoginBypassPlugin", SqliLoginBypassPlugin)
        self.plugin_manager.register_plugin("CmdInjectPlugin", CmdInjectPlugin)
        self.plugin_manager.register_plugin("ReverseShellHandler", ReverseShellHandler)
        self.plugin_manager.register_plugin("KernelPrivescPlugin", KernelPrivescPlugin)
        self.plugin_manager.register_plugin("UdfPrivescPlugin", UdfPrivescPlugin)
        self.plugin_manager.register_plugin("LfiPlugin", LfiPlugin)
        self.plugin_manager.register_plugin("CleanupPlugin", CleanupPlugin)

    def _initialize_chain(self) -> None:
        target_default_port = self.config.get("target", {}).get("default_port")
        if target_default_port:
            self.context["target"]["port"] = target_default_port
        self.attack_chain = flatten_attack_chain(self.config.get("attack_chain", []), self.context)

    async def run(self) -> None:
        """Run the main engine loop until completion or failure."""
        while True:
            event = await self.queue.get()
            logger.debug("Processing event %s", event)
            await self.dispatch(event)
            current_state = self.state_machine.get_current_state()
            if current_state in {AttackState.SUCCESS, AttackState.FAILED}:
                break
        self.evidence.save_report("output")
        if current_state == AttackState.CLEANUP:
            await self.cleanup_manager.cleanup(self.context)
        logger.info("Attack engine finished with state %s", current_state.value)

    async def dispatch(self, event: Dict[str, Any]) -> None:
        """Dispatch the event to the appropriate handler based on current state."""
        event_type = event.get("type")
        data = event.get("data")
        self.state_machine.transition(event_type)
        state = self.state_machine.get_current_state()
        if state == AttackState.RECON:
            await self._do_recon()
        elif state == AttackState.VULN_SCAN:
            await self._do_vuln_scan()
        elif state == AttackState.EXPLOIT:
            await self._do_exploit()
        elif state == AttackState.PRIVESC:
            await self._do_privesc()
        elif state == AttackState.PERSIST:
            await self._do_persist()
        elif state == AttackState.CLEANUP:
            await self._do_cleanup()
        elif state == AttackState.SUCCESS:
            logger.info("Attack succeeded")
        elif state == AttackState.FAILED:
            logger.warning("Attack failed")

    def trigger_event(self, event_type: EventType, data: Any = None) -> None:
        """Queue an event for processing."""
        self.queue.put_nowait({"type": event_type, "data": data})

    def _filter_steps(self, stage: str) -> List[Dict[str, Any]]:
        return [step for step in self.attack_chain if step.get("stage") == stage]

    async def _execute_step(self, step: Dict[str, Any]) -> None:
        plugin_name = step.get("plugin")
        params = step.get("params", {})
        try:
            result = await self.plugin_manager.execute_plugin(plugin_name, params, self.context)
            self.context.setdefault("plugin_results", {})[step["id"]] = result
            self.history_events.append({"step_id": step["id"], "result": result})
            self.evidence.log_step(step_id=step["id"], request={"plugin": plugin_name, "params": params}, response=result)
            self.trigger_event(EventType.PLUGIN_COMPLETE, {"step_id": step["id"], "result": result})
        except Exception as exc:
            logger.exception("Plugin failed: %s", exc)
            self.trigger_event(EventType.ERROR, {"step_id": step["id"], "error": str(exc)})

    async def _choose_and_execute(self, stage: str) -> None:
        steps = self._filter_steps(stage)
        available = [step for step in steps if self._dependencies_satisfied(step)]
        if not available:
            self.trigger_event(EventType.ERROR, {"reason": f"No available actions for stage {stage}"})
            return
        action_id, modified_params = self.ai_strategy.decide(self.context, available, self.history_events)
        selected = next((step for step in available if step.get("id") == action_id or step.get("plugin") == action_id), None)
        if not selected:
            selected = available[0]
        selected_params = {**selected.get("params", {}), **modified_params}
        selected = {**selected, "params": selected_params}
        await self._execute_step(selected)

    def _dependencies_satisfied(self, step: Dict[str, Any]) -> bool:
        for dependency in step.get("depends_on", []):
            if dependency not in self.context.get("plugin_results", {}):
                return False
        return True

    async def _do_recon(self) -> None:
        await self._choose_and_execute("recon")

    async def _do_vuln_scan(self) -> None:
        await self._choose_and_execute("vuln_scan")

    async def _do_exploit(self) -> None:
        await self._choose_and_execute("exploit")

    async def _do_privesc(self) -> None:
        await self._choose_and_execute("privesc")

    async def _do_persist(self) -> None:
        await self._choose_and_execute("persist")

    async def _do_cleanup(self) -> None:
        await self.cleanup_manager.cleanup(self.context)
        self.trigger_event(EventType.PLUGIN_COMPLETE, {"stage": "cleanup"})
