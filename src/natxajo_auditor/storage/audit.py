"""Registro de auditoría. Cada evento pasa por el bus persistente y lo escribe AuditConsumer.

Los eventos se clasifican en `operativo` (cambios de la plataforma) y `seguridad` (acceso, cuentas,
permisos y decisiones de confianza). Cada evento lleva la empresa a la que pertenece. Los eventos
de la instalación no pertenecen a ninguna empresa y solo los ve la plataforma.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Any

from natxajo_auditor.core.events import Event
from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.utilities import utc_now
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.outbox import EventOutbox

AUDIT_CONSUMER = "auditoria"
_SELECT = (
    "SELECT id, event_type, payload, created_at, category, company_id, actor FROM audit_events"
)


class AuditConsumer:
    """Escribe cada evento en audit_events. Es idempotente: el identificador del evento es único."""

    name = AUDIT_CONSUMER

    def accepts(self, event: Event) -> bool:
        return True

    def handle(self, event: Event, connection: sqlite3.Connection) -> None:
        connection.execute(
            "INSERT OR IGNORE INTO audit_events (event_id, event_type, payload, category, "
            "company_id, actor, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event.event_id,
                event.name,
                json.dumps(event.payload, ensure_ascii=False, sort_keys=True),
                event.category.value,
                event.company_id,
                event.actor,
                event.occurred_at,
            ),
        )


class AuditLog:
    def __init__(self, database: Database, outbox: EventOutbox | None = None) -> None:
        """Sin outbox, crea un bus propio con el consumidor de auditoría. El núcleo comparte el suyo."""
        if outbox is None:
            outbox = EventOutbox(database, utc_now)
            outbox.register(AuditConsumer())
        self._database = database
        self._outbox = outbox

    def record(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        connection: sqlite3.Connection | None = None,
        *,
        company_id: str | None = None,
        actor: str | None = None,
    ) -> None:
        """Registra un evento. Si se pasa una conexión, el evento entra en su transacción.

        Si no se indica empresa y la carga tiene un usuario, la empresa es la de esa cuenta.
        """
        if not event_type.strip():
            raise ValidationError("El tipo de evento de auditoría no puede estar vacío")
        scope = company_id if company_id is not None else self._company_of(payload, connection)
        self._outbox.emit(event_type, payload, company_id=scope, actor=actor, connection=connection)

    def list_events(
        self,
        limit: int = 50,
        *,
        company_id: str | None = None,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Eventos más recientes primero. Con company_id, solo los de esa empresa."""
        conditions: list[str] = []
        params: list[Any] = []
        if company_id is not None:
            conditions.append("company_id = ?")
            params.append(company_id)
        if category is not None:
            conditions.append("category = ?")
            params.append(category)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = self._database.fetchall(
            f"{_SELECT}{where} ORDER BY id DESC LIMIT ?", (*params, limit)
        )
        return [_to_event(row) for row in rows]

    def events_of_type(self, event_type: str) -> list[dict[str, Any]]:
        """Eventos de un tipo en orden cronológico."""
        rows = self._database.fetchall(
            f"{_SELECT} WHERE event_type = ? ORDER BY id ASC", (event_type,)
        )
        return [_to_event(row) for row in rows]

    def _company_of(
        self, payload: Mapping[str, Any], connection: sqlite3.Connection | None
    ) -> str | None:
        username = payload.get("username")
        if not isinstance(username, str):
            return None
        if connection is None:
            rows = self._database.fetchall(
                "SELECT company_id FROM accounts WHERE username = ?", (username,)
            )
        else:
            rows = connection.execute(
                "SELECT company_id FROM accounts WHERE username = ?", (username,)
            ).fetchall()
        return str(rows[0][0]) if rows else None


def _to_event(row: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "id": row[0],
        "event_type": row[1],
        "payload": json.loads(row[2]),
        "created_at": row[3],
        "category": row[4],
        "company_id": row[5],
        "actor": row[6],
    }
