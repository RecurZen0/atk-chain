from __future__ import annotations

import re
from collections import deque
from typing import Any, Dict, Iterable, List

import yaml

_TEMPLATE_PATTERN = re.compile(r"{{\s*([^{}\s]+)\s*}}")


def load_attack_chain(yaml_path: str) -> Dict[str, Any]:
    """Load and parse a YAML attack chain configuration file."""
    with open(yaml_path, "r", encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    if not isinstance(data, dict):
        raise ValueError("Attack chain YAML must contain a mapping at the root")
    return data


def _render_value(value: Any, context: Dict[str, Any]) -> Any:
    if isinstance(value, str):
        def _replace(match: re.Match) -> str:
            key = match.group(1)
            return str(_lookup_context(key, context) or "")

        return _TEMPLATE_PATTERN.sub(_replace, value)
    if isinstance(value, dict):
        return {k: _render_value(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [_render_value(item, context) for item in value]
    return value


def _lookup_context(path: str, context: Dict[str, Any]) -> Any:
    parts = path.split(".")
    node = context
    for part in parts:
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def render_params(params: Any, context: Dict[str, Any]) -> Any:
    """Render parameters using values from the current context."""
    return _render_value(params, context)


def topo_sort_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort attack chain steps by dependency order."""
    id_map = {step["id"]: step for step in steps}
    resolved = []
    visited = set()
    temp = set()

    def visit(step_id: str) -> None:
        if step_id in temp:
            raise ValueError(f"Circular dependency detected: {step_id}")
        if step_id in visited:
            return
        temp.add(step_id)
        step = id_map.get(step_id)
        if not step:
            raise ValueError(f"Missing dependency step: {step_id}")
        for dep in step.get("depends_on", []):
            visit(dep)
        temp.remove(step_id)
        visited.add(step_id)
        resolved.append(step)

    for step in steps:
        visit(step["id"])
    return resolved


def flatten_attack_chain(steps: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Render all step params and return a dependency-sorted configuration."""
    sorted_steps = topo_sort_steps(steps)
    for step in sorted_steps:
        step["params"] = render_params(step.get("params", {}), context)
    return sorted_steps
