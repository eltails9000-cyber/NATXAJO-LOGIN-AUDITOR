"""Guardián de operaciones: ninguna acción de la plataforma se ejecuta sin pasar por aquí.

Para cada operación comprueba, en este orden:
1. La sesión es válida y no ha caducado.
2. La cuenta tiene el permiso requerido.
3. El actor puede actuar sobre la empresa indicada. Sin empresa indicada, la operación es de
   plataforma y solo la cuenta de la plataforma la ejecuta.
4. Si la operación es crítica: el usuario la ha confirmado y ha reautenticado la sesión hace poco.

La empresa del actor se lee de su cuenta en la base de datos, nunca de la entrada del usuario.
Las denegaciones, las ejecuciones y los fallos de una operación autorizada quedan en la auditoría
(`operation.denied`, `operation.executed` y `operation.failed`). La auditoría no guarda contraseñas
ni fichas de sesión, y de un fallo registra solo el tipo de error.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TypeVar

from natxajo_auditor.core.contracts import (
    CLEANUP_PERMISSION,
    PLUGIN_QUARANTINE_RELEASE_PERMISSION,
    PLUGIN_VERSION_PERMISSION,
    SCOPE_DENIED,
)
from natxajo_auditor.core.exceptions import AuthorizationError
from natxajo_auditor.security.accounts import AccountStore
from natxajo_auditor.security.authorization import Authorizer
from natxajo_auditor.security.sessions import SessionStore
from natxajo_auditor.security.tenancy import Actor, may_act_on
from natxajo_auditor.storage.audit import AuditLog

T = TypeVar("T")
LOG = logging.getLogger(__name__)

CRITICAL_PERMISSIONS: frozenset[str] = frozenset(
    {
        "versiones:nucleo:version:ejecutar",
        "modulos:nucleo:modulo:ejecutar",
        "seguridad:nucleo:cuenta:administrar",
        "seguridad:nucleo:empresa:administrar",
        "seguridad:nucleo:permiso:aprobar",
        "almacenamiento:nucleo:copia:restaurar",
        # Confianza global: editores de confianza y decisiones de revisión de terceros.
        "plugins:nucleo:editor:administrar",
        "plugins:nucleo:revision:administrar",
        # Borra archivos temporales del disco: destructiva, exige confirmación y reautenticación.
        CLEANUP_PERMISSION,
        # Cambian qué versión de un plugin puede habilitarse: exigen confirmación y reautenticación.
        PLUGIN_VERSION_PERMISSION,
        PLUGIN_QUARANTINE_RELEASE_PERMISSION,
    }
)


def _may_run_in(actor: Actor, company_id: str | None) -> bool:
    """Una operación sin empresa indicada es de plataforma: no se ejecuta por omisión.

    Así un llamador que olvida pasar la empresa no concede a una cuenta de empresa las
    operaciones de infraestructura (versiones, módulos, plugins, copias).
    """
    if company_id is None:
        return actor.is_platform
    return may_act_on(actor, company_id)


class OperationGuard:
    def __init__(
        self,
        sessions: SessionStore,
        authorizer: Authorizer,
        audit: AuditLog,
        accounts: AccountStore,
    ) -> None:
        self._sessions = sessions
        self._authorizer = authorizer
        self._audit = audit
        self._accounts = accounts

    def actor_for(self, token: str) -> Actor:
        """Actor de una sesión válida. La empresa sale de la cuenta."""
        session = self._sessions.validate(token)
        return self._actor(session.username, session.session_id)

    def username_for(self, token: str) -> str:
        """Cuenta de una sesión válida. Sin sesión válida no hay actor y la operación no empieza."""
        return self._sessions.validate(token).username

    def check_scope(self, token: str, company_id: str, permission: str) -> Actor:
        """Comprueba que la sesión puede actuar sobre la empresa indicada. Audita la denegación."""
        actor = self.actor_for(token)
        if not may_act_on(actor, company_id):
            self._record_denied(actor, permission, SCOPE_DENIED, company_id)
            error = AuthorizationError(SCOPE_DENIED)
            _mark(error)
            raise error
        return actor

    def run(
        self,
        token: str,
        permission: str,
        operation: Callable[[], T],
        *,
        confirmed: bool = False,
        company_id: str | None = None,
    ) -> T:
        """Ejecuta operation si la sesión la autoriza. Registra denegación, éxito o fallo.

        Un error al escribir en la auditoría no oculta el resultado de la operación: si la
        operación ya se ejecutó, se devuelve su resultado y el fallo del registro se anota en el
        log del proceso. Si la operación falla, se relanza su excepción original.
        """
        session = self._sessions.validate(token)
        actor = self._actor(session.username, session.session_id)
        critical = permission in CRITICAL_PERMISSIONS
        try:
            self._authorizer.require(actor.username, permission)
            if not _may_run_in(actor, company_id):
                raise AuthorizationError(SCOPE_DENIED)
            if critical and not confirmed:
                raise AuthorizationError("operación crítica: se requiere confirmación")
            if critical and not self._sessions.recently_reauthenticated(session):
                raise AuthorizationError("operación crítica: reautentique la sesión")
        except AuthorizationError as exc:
            self._record_denied(actor, permission, str(exc), company_id)
            _mark(exc)
            raise
        try:
            result = operation()
        except BaseException as exc:
            if not _is_marked(exc):
                self._note_failure(actor, permission, critical, company_id, exc)
                _mark(exc)
            raise
        self._note_success(actor, permission, critical, company_id)
        return result

    def _actor(self, username: str, session_id: int) -> Actor:
        return Actor(
            username=username,
            company_id=self._accounts.company_of(username),
            session_id=session_id,
        )

    def _record_denied(
        self, actor: Actor, permission: str, reason: str, target: str | None
    ) -> None:
        payload: dict[str, str] = {
            "username": actor.username,
            "permission": permission,
            "reason": reason,
        }
        if target is not None and target != actor.company_id:
            payload["empresa_destino"] = target
        self._audit.record("operation.denied", payload, company_id=actor.company_id)

    def _note_success(
        self,
        actor: Actor,
        permission: str,
        critical: bool,
        company_id: str | None,
    ) -> None:
        try:
            self._audit.record(
                "operation.executed",
                {"username": actor.username, "permission": permission, "critical": critical},
                company_id=company_id or actor.company_id,
            )
        # La operación ya se hizo: un fallo del registro se anota, pero no oculta su resultado.
        except Exception:
            LOG.exception("No se pudo registrar la ejecución de %s", permission)

    def _note_failure(
        self,
        actor: Actor,
        permission: str,
        critical: bool,
        company_id: str | None,
        error: BaseException,
    ) -> None:
        """Registra el fallo sin el texto del error: solo su tipo. Así no se copian rutas,
        consultas ni datos que el error pudiera llevar dentro."""
        try:
            self._audit.record(
                "operation.failed",
                {
                    "username": actor.username,
                    "permission": permission,
                    "critical": critical,
                    "error": type(error).__name__,
                },
                company_id=company_id or actor.company_id,
            )
        # El error original es el que debe llegar al llamador: el del registro solo se anota.
        except Exception:
            LOG.exception("No se pudo registrar el fallo de %s", permission)


_MARK = "_natxajo_registrado"


def _mark(error: BaseException) -> None:
    """Marca una excepción ya registrada como denegación o fallo. Una operación anidada que
    relanza el mismo error no lo registra dos veces."""
    setattr(error, _MARK, True)


def _is_marked(error: BaseException) -> bool:
    return bool(getattr(error, _MARK, False))
