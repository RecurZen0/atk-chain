from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

import yaml


class AIStrategy:
    """AI decision module to match rules or delegate to an optional LLM."""

    def __init__(self, rule_yaml_path: str, llm_model: Optional[str] = None) -> None:
        self.rule_yaml_path = rule_yaml_path
        self.llm_model = llm_model
        self.rules = self._load_rules(rule_yaml_path)

    def _load_rules(self, path: str) -> List[Dict[str, Any]]:
        with open(path, "r", encoding="utf-8") as stream:
            data = yaml.safe_load(stream)
        return data.get("rules", []) if isinstance(data, dict) else []

    def decide(
        self,
        context: Dict[str, Any],
        available_actions: List[Dict[str, Any]],
        history_events: List[Dict[str, Any]],
    ) -> Tuple[str, Dict[str, Any]]:
        """Choose the next action and optionally adjust parameters."""
        for rule in self.rules:
            if self._match_rule(rule.get("if", {}), context, history_events):
                action = rule.get("then", {}).get("action")
                params = rule.get("then", {}).get("params", {})
                if action:
                    return action, params

        if self.llm_model:
            prompt = self._build_prompt(context, available_actions, history_events)
            response = self._call_llm(prompt)
            if response and response.get("action"):
                return response["action"], response.get("params", {})

        if available_actions:
            chosen = available_actions[0]
            return chosen.get("id", chosen.get("plugin", "unknown")), chosen.get("params", {})

        raise RuntimeError("No available actions for AI strategy to choose")

    def _match_rule(self, conditions: Any, context: Dict[str, Any], history: List[Dict[str, Any]]) -> bool:
        if not conditions:
            return False
        if isinstance(conditions, dict):
            for key, expected in conditions.items():
                if key == "and" and isinstance(expected, list):
                    if not all(self._match_rule(item, context, history) for item in expected):
                        return False
                    continue
                if key == "or" and isinstance(expected, list):
                    if not any(self._match_rule(item, context, history) for item in expected):
                        return False
                    continue
                operator = "=="
                condition_key = key
                if isinstance(key, str) and " contains" in key:
                    condition_key, operator = key.split(" contains", 1)
                    operator = "contains"
                actual = self._resolve_condition_value(condition_key.strip(), context, history)
                if operator == "contains":
                    if expected is None or str(expected) not in str(actual):
                        return False
                else:
                    if actual != expected:
                        return False
            return True
        return False

    def _resolve_condition_value(self, key: str, context: Dict[str, Any], history: List[Dict[str, Any]]) -> Any:
        if key.startswith("context."):
            path = key[len("context.") :]
            return self._lookup_context(path, context)
        if key == "last_plugin_result":
            if not history:
                return None
            return history[-1].get("result")
        return None

    @staticmethod
    def _lookup_context(path: str, context: Dict[str, Any]) -> Any:
        node = context
        for part in path.split("."):
            if isinstance(node, dict):
                node = node.get(part)
            else:
                return None
        return node

    def _build_prompt(self, context: Dict[str, Any], actions: List[Dict[str, Any]], history: List[Dict[str, Any]]) -> str:
        return json.dumps({"context": context, "actions": actions, "history": history}, indent=2)

    def _call_llm(self, prompt: str) -> Optional[Dict[str, Any]]:
        # Optional local LLM integration placeholder.
        return None
