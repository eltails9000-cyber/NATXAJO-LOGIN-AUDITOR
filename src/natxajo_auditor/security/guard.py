"""Guardián de operaciones: ninguna acción de la plataforma se ejecuta sin pasar por aquí.

Para cada operación comprueba, en este orden:
1. La sesión es válida y no ha caducado.
2. La cuenta tiene el permiso requerido.
3. El actor puede actuar sobre la empresa indicada. Sin empresa indicada, la operación es de
   plataforma y solo la cuenta de la plataforma la ejecuta.
4. Si la operación es crítica: el usuario la ha confirmado y ha reautenticado la sesión hace poco.

La empresa del actor se lee de su cuenta en la base de datos, nunca de la entrada del usuario.
Las denegaciones y las ejecuciones quedan en la auditoría. La auditoría no guarda contraseñas ni
fichas de sesión.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from natxajo_auditor.core.exceptions import AuthorizationError
from natxajo_auditor.security.accounts import AccountStore
from natxajo_auditor.security.authorization import Authorizer
from natxajo_auditor.security.sessions import SessionStore
from natxajo_auditor.security.tenancy import SCOPE_DENIED, Actor, may_act_on
from natxajo_auditor.storage.audit import AuditLog

T = TypeVar("T")

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
            raise AuthorizationError(SCOPE_DENIED)
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
            raise
        result = operation()
        self._audit.record(
            "operation.executed",
            {"username": actor.username, "permission": permission, "critical": critical},
            company_id=company_id or actor.company_id,
        )
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
