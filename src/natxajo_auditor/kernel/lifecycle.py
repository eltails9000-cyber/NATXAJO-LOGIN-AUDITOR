"""Máquina de estados del núcleo. Las transiciones no permitidas se rechazan."""

from __future__ import annotations

from enum import Enum

from natxajo_auditor.core.exceptions import LifecycleError


class LifecycleState(str, Enum):
    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


_ALLOWED: dict[LifecycleState, frozenset[LifecycleState]] = {
    LifecycleState.CREATED: frozenset({LifecycleState.STARTING, LifecycleState.STOPPED}),
    LifecycleState.STARTING: frozenset({LifecycleState.RUNNING, LifecycleState.FAILED}),
    LifecycleState.RUNNING: frozenset({LifecycleState.STOPPING}),
    LifecycleState.FAILED: frozenset({LifecycleState.STOPPING}),
    LifecycleState.STOPPING: frozenset({LifecycleState.STOPPED, LifecycleState.FAILED}),
    LifecycleState.STOPPED: frozenset(),
}


class Lifecycle:
    def __init__(self) -> None:
        self._state = LifecycleState.CREATED

    @property
    def state(self) -> LifecycleState:
        return self._state

    def transition(self, target: LifecycleState) -> None:
        if target not in _ALLOWED[self._state]:
            raise LifecycleError(f"Transición no permitida: {self._state.value} -> {target.value}")
        self._state = target
