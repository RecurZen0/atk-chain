from __future__ import annotations

import logging
from typing import Any, Dict, List, Type

logger = logging.getLogger(__name__)


class BasePlugin:
    """Base class for all attack plugins."""

    async def run(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError("Plugin must implement async run()")


class PluginManager:
    """Manage registration and execution of attack plugins."""

    def __init__(self) -> None:
        self._registry: Dict[str, Type[BasePlugin]] = {}

    def register_plugin(self, name: str, plugin_class: Type[BasePlugin]) -> None:
        self._registry[name] = plugin_class
        logger.debug("Registered plugin %s", name)

    async def execute_plugin(self, name: str, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        plugin_class = self._registry.get(name)
        if plugin_class is None:
            raise ValueError(f"Plugin not registered: {name}")
        plugin = plugin_class()
        return await plugin.run(params, context)
