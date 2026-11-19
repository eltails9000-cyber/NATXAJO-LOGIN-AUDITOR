"""Registro de auditoría de operaciones sensibles, persistido en la base de datos."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Any

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.storage.database import Database

_SELECT = "SELECT id, event_type, payload, created_at FROM audit_events"


class AuditLog:
    def __init__(self, database: Database) -> None:
        self._database = database

    def record(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        connection: sqlite3.Connection | None = None,
    ) -> None:
        """Registra un evento. Si se pasa una conexión, el evento entra en su transacción."""
        if not event_type.strip():
            raise ValidationError("El tipo de evento de auditoría no puede estar vacío")
        sql = "INSERT INTO audit_events (event_type, payload) VALUES (?, ?)"
        params = (event_type, json.dumps(dict(payload), ensure_ascii=False, sort_keys=True))
        if connection is None:
            self._database.execute(sql, params)
        else:
            connection.execute(sql, params)

    def list_events(self, limit: int = 50) -> list[dict[str, Any]]:
        """Eventos más recientes primero."""
        rows = self._database.fetchall(f"{_SELECT} ORDER BY id DESC LIMIT ?", (limit,))
        return [_to_event(row) for row in rows]

    def events_of_type(self, event_type: str) -> list[dict[str, Any]]:
        """Eventos de un tipo en orden cronológico."""
        rows = self._database.fetchall(
            f"{_SELECT} WHERE event_type = ? ORDER BY id ASC", (event_type,)
        )
        return [_to_event(row) for row in rows]


def _to_event(row: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "id": row[0],
        "event_type": row[1],
        "payload": json.loads(row[2]),
        "created_at": row[3],
    }
