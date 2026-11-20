"""Guardián de operaciones: ninguna acción de la plataforma se ejecuta sin pasar por aquí.

Para cada operación comprueba, en este orden:
1. La sesión es válida y no ha caducado.
2. La cuenta tiene el permiso requerido.
3. Si la operación es crítica: el usuario la ha confirmado y ha reautenticado la sesión hace poco.

Las denegaciones y las ejecuciones quedan en la auditoría. La auditoría no guarda contraseñas ni
fichas de sesión.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from natxajo_auditor.core.exceptions import AuthorizationError
from natxajo_auditor.security.authorization import Authorizer
from natxajo_auditor.security.sessions import SessionStore
from natxajo_auditor.storage.audit import AuditLog

T = TypeVar("T")

CRITICAL_PERMISSIONS: frozenset[str] = frozenset(
    {
        "versiones:nucleo:version:ejecutar",
        "modulos:nucleo:modulo:ejecutar",
        "seguridad:nucleo:cuenta:administrar",
        "seguridad:nucleo:permiso:aprobar",
        "almacenamiento:nucleo:copia:restaurar",
    }
)


class OperationGuard:
    def __init__(self, sessions: SessionStore, authorizer: Authorizer, audit: AuditLog) -> None:
        self._sessions = sessions
        self._authorizer = authorizer
        self._audit = audit

    def run(
        self,
        token: str,
        permission: str,
        operation: Callable[[], T],
        *,
        confirmed: bool = False,
    ) -> T:
        session = self._sessions.validate(token)
        critical = permission in CRITICAL_PERMISSIONS
        try:
            self._authorizer.require(session.username, permission)
            if critical and not confirmed:
                raise AuthorizationError("operación crítica: se requiere confirmación")
            if critical and not self._sessions.recently_reauthenticated(session):
                raise AuthorizationError("operación crítica: reautentique la sesión")
        except AuthorizationError as exc:
            self._audit.record(
                "operation.denied",
                {"username": session.username, "permission": permission, "reason": str(exc)},
            )
            raise
        result = operation()
        self._audit.record(
            "operation.executed",
            {"username": session.username, "permission": permission, "critical": critical},
        )
        return result
