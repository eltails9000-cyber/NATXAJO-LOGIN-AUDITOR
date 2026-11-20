"""Permisos temporales: solicitud, aprobación, rechazo y revocación.

Reglas:
- Una solicitud no concede nada hasta que se aprueba.
- Nadie aprueba su propia solicitud.
- Quien aprueba debe tener el permiso de aprobar y también el permiso que aprueba (anti-escalada).
- Un permiso temporal caduca a los minutos indicados. Los minutos están acotados a MAX_GRANT_MINUTES.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.core.utilities import Clock, from_iso, to_iso
from natxajo_auditor.core.validation import require_text
from natxajo_auditor.security.permissions import Permission, parse_permission
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database

MAX_GRANT_MINUTES = 240
APPROVE_PERMISSION = "seguridad:nucleo:permiso:aprobar"
REVOKE_PERMISSION = "seguridad:nucleo:permiso:revocar"
PENDING = "pending"
ACTIVE = "active"
REJECTED = "rejected"
REVOKED = "revoked"

Can = Callable[[str, str], bool]


@dataclass(frozen=True)
class GrantRecord:
    grant_id: int
    username: str
    permission: str
    minutes: int
    reason: str
    requested_by: str
    approved_by: str | None
    status: str
    expires_at: datetime | None


class GrantStore:
    def __init__(self, database: Database, audit: AuditLog, clock: Clock) -> None:
        self._database = database
        self._audit = audit
        self._clock = clock

    def request(
        self, requester: str, username: str, permission: str, minutes: int, reason: str
    ) -> int:
        target = parse_permission(permission, source="permiso temporal")
        if not 1 <= minutes <= MAX_GRANT_MINUTES:
            raise ValidationError(f"la duración debe estar entre 1 y {MAX_GRANT_MINUTES} minutos")
        reason = require_text(reason, "motivo", "permiso temporal")
        if not self._account_exists(username):
            raise ValidationError(f"la cuenta no existe: {username}")
        with self._database.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO permission_grants (username, permission, minutes, reason, "
                "requested_by, status) VALUES (?, ?, ?, ?, ?, ?)",
                (username, str(target), minutes, reason, requester, PENDING),
            )
            grant_id = int(cursor.lastrowid or 0)
            self._audit.record(
                "grant.requested",
                {"grant": grant_id, "username": username, "permission": str(target)},
                connection=connection,
            )
        return grant_id

    def approve(self, approver: str, grant_id: int, can: Can) -> GrantRecord:
        record = self.get(grant_id)
        self._require_pending(record)
        if approver == record.requested_by:
            raise AuthorizationError("no puede aprobar su propia solicitud")
        if not can(approver, APPROVE_PERMISSION):
            raise AuthorizationError("no tiene permiso para aprobar solicitudes")
        if not can(approver, record.permission):
            raise AuthorizationError(
                f"no puede aprobar un permiso que no posee: {record.permission}"
            )
        expires = self._clock() + timedelta(minutes=record.minutes)
        with self._database.transaction() as connection:
            connection.execute(
                "UPDATE permission_grants SET status = ?, approved_by = ?, expires_at = ?, "
                "updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (ACTIVE, approver, to_iso(expires), grant_id),
            )
            self._audit.record(
                "grant.approved",
                {"grant": grant_id, "approver": approver, "permission": record.permission},
                connection=connection,
            )
        return self.get(grant_id)

    def reject(self, actor: str, grant_id: int, can: Can) -> GrantRecord:
        """Rechaza una solicitud. Quien la hizo puede retirarla sin más permisos."""
        record = self.get(grant_id)
        self._require_pending(record)
        if actor != record.requested_by and not can(actor, APPROVE_PERMISSION):
            raise AuthorizationError("no tiene permiso para rechazar solicitudes")
        self._set_status(grant_id, REJECTED, actor, "grant.rejected")
        return self.get(grant_id)

    def revoke(self, actor: str, grant_id: int, can: Can) -> GrantRecord:
        record = self.get(grant_id)
        if record.status != ACTIVE:
            raise ValidationError("solo se puede revocar un permiso activo")
        if not can(actor, REVOKE_PERMISSION):
            raise AuthorizationError("no tiene permiso para revocar permisos temporales")
        self._set_status(grant_id, REVOKED, actor, "grant.revoked")
        return self.get(grant_id)

    def get(self, grant_id: int) -> GrantRecord:
        rows = self._database.fetchall(_SELECT + " WHERE id = ?", (grant_id,))
        if not rows:
            raise ValidationError(f"solicitud de permiso no existe: {grant_id}")
        return _to_record(rows[0])

    def list_grants(self) -> list[GrantRecord]:
        return [_to_record(row) for row in self._database.fetchall(_SELECT + " ORDER BY id")]

    def active_permissions(self, username: str) -> list[Permission]:
        """Permisos temporales activos y no caducados de una cuenta."""
        now = self._clock()
        rows = self._database.fetchall(
            "SELECT permission, expires_at FROM permission_grants "
            "WHERE username = ? AND status = ?",
            (username, ACTIVE),
        )
        result: list[Permission] = []
        for permission, expires_text in rows:
            expires = from_iso(None if expires_text is None else str(expires_text))
            if expires is not None and expires > now:
                result.append(parse_permission(str(permission), source="permiso temporal"))
        return result

    def _require_pending(self, record: GrantRecord) -> None:
        if record.status != PENDING:
            raise ValidationError(f"la solicitud {record.grant_id} ya no está pendiente")

    def _set_status(self, grant_id: int, status: str, actor: str, event: str) -> None:
        with self._database.transaction() as connection:
            connection.execute(
                "UPDATE permission_grants SET status = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE id = ?",
                (status, grant_id),
            )
            self._audit.record(event, {"grant": grant_id, "actor": actor}, connection=connection)

    def _account_exists(self, username: str) -> bool:
        return bool(
            self._database.fetchall("SELECT 1 FROM accounts WHERE username = ?", (username,))
        )


_SELECT = (
    "SELECT id, username, permission, minutes, reason, requested_by, approved_by, status, "
    "expires_at FROM permission_grants"
)


def _to_record(row: tuple[object, ...]) -> GrantRecord:
    approved = row[6]
    expires = row[8]
    return GrantRecord(
        grant_id=int(str(row[0])),
        username=str(row[1]),
        permission=str(row[2]),
        minutes=int(str(row[3])),
        reason=str(row[4]),
        requested_by=str(row[5]),
        approved_by=None if approved is None else str(approved),
        status=str(row[7]),
        expires_at=from_iso(None if expires is None else str(expires)),
    )
