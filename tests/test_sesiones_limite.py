"""Límite de sesiones de la cuenta: rechazo auditado y consulta de vigencia sin renovar.

- Un inicio rechazado por el límite queda en la auditoría (`session.limit_reached`). El registro se
  escribe fuera de la transacción que se revierte al rechazar.
- `is_live` dice si una ficha sigue vigente sin renovar su inactividad: consultarla no puede
  alargar una sesión.
- El servidor de la interfaz atiende peticiones de una en una. Las garantías de los pools de
  sesiones de la interfaz dependen de eso: esta prueba avisa si el servidor pasa a ser multihilo.
"""

from __future__ import annotations

from datetime import timedelta
from socketserver import ThreadingMixIn

import pytest

from natxajo_auditor.core.exceptions import SessionLimitError
from natxajo_auditor.core.utilities import utc_now
from natxajo_auditor.interfaces.gui.server import GuiServer
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.security.sessions import IDLE_TIMEOUT, MAX_CONCURRENT_SESSIONS
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER


def test_the_limit_is_refused_and_audited(kernel: Kernel, admin: tuple[str, str]) -> None:
    for _ in range(MAX_CONCURRENT_SESSIONS):
        kernel.security.login(ADMIN_USER, ADMIN_PASSWORD)
    with pytest.raises(SessionLimitError):
        kernel.security.login(ADMIN_USER, ADMIN_PASSWORD)
    eventos = kernel.audit.events_of_type("session.limit_reached")
    assert len(eventos) == 1
    assert eventos[0]["payload"] == {"username": ADMIN_USER}


def test_is_live_tells_validity_without_renewing_the_idle_timer(
    kernel: Kernel, admin: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sessions = kernel.security.sessions
    instante = {"ahora": utc_now()}
    monkeypatch.setattr(sessions, "_clock", lambda: instante["ahora"])
    token = sessions.open(ADMIN_USER)
    instante["ahora"] += timedelta(minutes=10)
    assert sessions.is_live(token) is True
    # 16 minutos desde la última actividad real: si is_live la hubiera renovado, seguiría viva.
    instante["ahora"] += timedelta(minutes=6)
    assert IDLE_TIMEOUT < timedelta(minutes=16)
    assert sessions.is_live(token) is False


def test_is_live_is_false_for_unknown_and_closed_sessions(
    kernel: Kernel, admin: tuple[str, str]
) -> None:
    sessions = kernel.security.sessions
    assert sessions.is_live("ficha-que-no-existe") is False
    token = kernel.security.login(ADMIN_USER, ADMIN_PASSWORD)
    assert sessions.is_live(token) is True
    kernel.security.logout(token)
    assert sessions.is_live(token) is False


def test_the_gui_server_is_single_threaded_as_the_session_pools_assume() -> None:
    assert not issubclass(GuiServer, ThreadingMixIn)
