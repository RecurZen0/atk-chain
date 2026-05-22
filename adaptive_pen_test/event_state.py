from __future__ import annotations

import enum
from typing import Any, Dict


class EventType(enum.Enum):
    START = "start"
    TIMER = "timer"
    NETWORK_RESPONSE = "network_response"
    PLUGIN_COMPLETE = "plugin_complete"
    SENSOR_ALERT = "sensor_alert"
    AI_DECISION = "ai_decision"
    CLEANUP = "cleanup"
    ERROR = "error"


class AttackState(enum.Enum):
    IDLE = "idle"
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    EXPLOIT = "exploit"
    PRIVESC = "privesc"
    PERSIST = "persist"
    CLEANUP = "cleanup"
    SUCCESS = "success"
    FAILED = "failed"


class StateMachine:
    """Manage attack state transitions using a simple state table."""

    def __init__(self, initial_state: AttackState = AttackState.IDLE) -> None:
        self._state = initial_state
        self._transitions: Dict[AttackState, Dict[EventType, AttackState]] = {
            AttackState.IDLE: {
                EventType.START: AttackState.RECON,
                EventType.ERROR: AttackState.FAILED,
            },
            AttackState.RECON: {
                EventType.PLUGIN_COMPLETE: AttackState.VULN_SCAN,
                EventType.SENSOR_ALERT: AttackState.RECON,
                EventType.ERROR: AttackState.FAILED,
            },
            AttackState.VULN_SCAN: {
                EventType.PLUGIN_COMPLETE: AttackState.EXPLOIT,
                EventType.SENSOR_ALERT: AttackState.RECON,
                EventType.ERROR: AttackState.FAILED,
            },
            AttackState.EXPLOIT: {
                EventType.PLUGIN_COMPLETE: AttackState.PRIVESC,
                EventType.SENSOR_ALERT: AttackState.RECON,
                EventType.ERROR: AttackState.FAILED,
            },
            AttackState.PRIVESC: {
                EventType.PLUGIN_COMPLETE: AttackState.PERSIST,
                EventType.SENSOR_ALERT: AttackState.CLEANUP,
                EventType.ERROR: AttackState.FAILED,
            },
            AttackState.PERSIST: {
                EventType.PLUGIN_COMPLETE: AttackState.SUCCESS,
                EventType.CLEANUP: AttackState.CLEANUP,
                EventType.ERROR: AttackState.FAILED,
            },
            AttackState.CLEANUP: {
                EventType.PLUGIN_COMPLETE: AttackState.SUCCESS,
                EventType.ERROR: AttackState.FAILED,
            },
            AttackState.SUCCESS: {},
            AttackState.FAILED: {},
        }

    def transition(self, event_type: EventType, data: Any = None) -> AttackState:
        """Transition to a new state based on the incoming event."""
        available = self._transitions.get(self._state, {})
        next_state = available.get(event_type, self._state)
        self._state = next_state
        return self._state

    def get_current_state(self) -> AttackState:
        """Return the current attack state."""
        return self._state
