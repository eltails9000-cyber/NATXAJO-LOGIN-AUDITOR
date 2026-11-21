"""Bus de eventos persistente: outbox transaccional con consumidores idempotentes.

Ciclo de vida de un evento:
1. Se emite dentro de la transacción del cambio que lo origina. Si el cambio se revierte, el
   evento desaparece con él.
2. Tras confirmar la transacción se entrega a cada consumidor. Cada entrega se hace en una
   transacción propia que incluye el efecto del consumidor y el registro de la entrega. Por eso
   un consumidor no aplica dos veces el mismo evento.
3. Si un consumidor falla, la transacción de esa entrega se revierte, el fallo se guarda en el
   evento y el evento se reintenta en la siguiente pasada. La entrega sigue en orden: un evento
   pendiente bloquea a los posteriores hasta resolverse o pasar a la cola de fallidos.
4. Tras MAX_ATTEMPTS fallos el evento pasa a `dead`. Se puede reencolar con requeue_dead().
5. Al arrancar el núcleo se reintentan los eventos pendientes que quedaron sin entregar.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from natxajo_auditor.core.events import Category, Event, build_event
from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.utilities import Clock, to_iso
from natxajo_auditor.storage.database import Database

MAX_ATTEMPTS = 5
MAX_ERROR_LENGTH = 200
DISPATCH_BATCH = 200

PENDING = "pending"
DELIVERED = "delivered"
DEAD = "dead"

# Tablas de la plataforma que ningún consumidor puede escribir: contabilidad del bus, cuentas,
# sesiones, permisos, instalación, versiones y módulos. Una tabla nueva de la plataforma debe
# añadirse aquí. La auditoría tiene regla propia (AUDIT_TABLE).
PROTECTED_TABLES = frozenset(
    {
        "account_roles",
        "accounts",
        "companies",
        "event_deliveries",
        "event_outbox",
        "installation",
        "module_states",
        "permission_grants",
        "platform_metadata",
        "plugin_installs",
        "plugin_publishers",
        "plugin_reviews",
        "role_grants",
        "role_parents",
        "roles",
        "schema_migrations",
        "sessions",
    }
)
AUDIT_TABLE = "audit_events"

# Acciones de SQLite que un consumidor puede ejecutar. Cualquier otra (DDL, PRAGMA, ATTACH...) se
# deniega: un consumidor no cambia el esquema ni la configuración de la base de datos.
_ALLOWED_ACTIONS = frozenset(
    {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
        sqlite3.SQLITE_RECURSIVE,
        sqlite3.SQLITE_INSERT,
        sqlite3.SQLITE_UPDATE,
        sqlite3.SQLITE_DELETE,
        sqlite3.SQLITE_SAVEPOINT,
    }
)
_WRITE_ACTIONS = frozenset({sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE})

SqliteAuthorizer = Callable[[int, str | None, str | None, str | None, str | None], int]


def _consumer_policy(writes_audit: bool) -> SqliteAuthorizer:
    """Autorizador de SQLite para ejecutar un consumidor.

    Un consumidor puede leer, y escribir en tablas que no son de la plataforma. La auditoría
    solo admite inserciones, y solo al consumidor que la escribe (`writes_audit`): ni se edita
    ni se borra el historial.
    """

    def policy(
        action: int,
        table: str | None,
        _column: str | None,
        _database: str | None,
        _trigger: str | None,
    ) -> int:
        if action not in _ALLOWED_ACTIONS:
            return sqlite3.SQLITE_DENY
        if action in _WRITE_ACTIONS and table is not None:
            if table in PROTECTED_TABLES:
                return sqlite3.SQLITE_DENY
            if table == AUDIT_TABLE and (action != sqlite3.SQLITE_INSERT or not writes_audit):
                return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    return policy


class Consumer(Protocol):
    """Consumidor de eventos. handle escribe solo a través de la conexión recibida.

    Un consumidor que escriba en la auditoría declara `writes_audit = True`. Cualquier otra
    escritura sobre las tablas de la plataforma se rechaza con el autorizador de `_consumer_policy`.
    """

    name: str

    def accepts(self, event: Event) -> bool: ...

    def handle(self, event: Event, connection: sqlite3.Connection) -> None: ...


@dataclass(frozen=True)
class DispatchReport:
    delivered: int = 0
    failed: int = 0
    dead: int = 0


class EventOutbox:
    def __init__(
        self, database: Database, clock: Clock, *, max_attempts: int = MAX_ATTEMPTS
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts debe ser al menos 1")
        self._database = database
        self._clock = clock
        self._max_attempts = max_attempts
        self._consumers: dict[str, Consumer] = {}
        self._dispatching = False

    def register(self, consumer: Consumer) -> None:
        if consumer.name in self._consumers:
            raise ValidationError(f"el consumidor ya está registrado: {consumer.name}")
        self._consumers[consumer.name] = consumer

    def emit(
        self,
        name: str,
        payload: Mapping[str, Any],
        *,
        company_id: str | None = None,
        actor: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> Event:
        """Valida y guarda el evento. Se entrega cuando su transacción se confirma."""
        event = build_event(
            name,
            payload,
            event_id=uuid.uuid4().hex,
            occurred_at=self._clock(),
            company_id=company_id,
            actor=actor,
        )
        if connection is None:
            with self._database.transaction() as own:
                _append(own, event)
        else:
            _append(connection, event)
        self._database.after_commit(self._dispatch_after_commit)
        return event

    def _dispatch_after_commit(self) -> None:
        self.dispatch_pending()

    def dispatch_pending(self) -> DispatchReport:
        """Entrega los eventos pendientes. Es seguro llamarla varias veces."""
        if self._dispatching:
            return DispatchReport()
        self._dispatching = True
        try:
            return self._dispatch()
        finally:
            self._dispatching = False

    def pending_count(self) -> int:
        rows = self._database.fetchall(
            "SELECT COUNT(*) FROM event_outbox WHERE status = ?", (PENDING,)
        )
        return int(rows[0][0])

    def dead_events(self) -> list[dict[str, Any]]:
        rows = self._database.fetchall(
            "SELECT event_id, name, attempts, last_error FROM event_outbox "
            "WHERE status = ? ORDER BY seq",
            (DEAD,),
        )
        return [
            {"event_id": row[0], "name": row[1], "attempts": row[2], "last_error": row[3]}
            for row in rows
        ]

    def requeue_dead(self) -> int:
        """Devuelve a la cola los eventos fallidos, con el contador de intentos a cero."""
        with self._database.transaction() as connection:
            cursor = connection.execute(
                "UPDATE event_outbox SET status = ?, attempts = 0, last_error = NULL "
                "WHERE status = ?",
                (PENDING, DEAD),
            )
            return int(cursor.rowcount)

    def _dispatch(self) -> DispatchReport:
        delivered = failed = dead = 0
        rows = self._database.fetchall(
            "SELECT event_id, name, category, company_id, actor, occurred_at, payload "
            "FROM event_outbox WHERE status = ? ORDER BY seq LIMIT ?",
            (PENDING, DISPATCH_BATCH),
        )
        for row in rows:
            event = _to_event(row)
            failure = self._deliver(event)
            if failure is None:
                self._database.execute(
                    "UPDATE event_outbox SET status = ?, last_error = NULL WHERE event_id = ?",
                    (DELIVERED, event.event_id),
                )
                delivered += 1
                continue
            failed += 1
            if self._record_failure(event.event_id, failure) == DEAD:
                dead += 1
                continue
            # Pendiente: se corta la entrega para no adelantar eventos posteriores.
            break
        return DispatchReport(delivered=delivered, failed=failed, dead=dead)

    def _deliver(self, event: Event) -> tuple[str, Exception] | None:
        """Entrega el evento a los consumidores pendientes. Devuelve el primer fallo, si lo hay."""
        for consumer in self._consumers.values():
            if not consumer.accepts(event):
                continue
            try:
                with self._database.transaction() as connection:
                    # La comprobación va dentro de la transacción de escritura: otro despachador
                    # que confirme esta entrega antes de que empiece esta transacción la hace
                    # visible aquí, y el consumidor no se ejecuta dos veces.
                    if self._delivered_to(event.event_id, consumer.name):
                        continue
                    _run_consumer(consumer, event, connection)
                    connection.execute(
                        "INSERT OR IGNORE INTO event_deliveries (event_id, consumer, delivered_at) "
                        "VALUES (?, ?, ?)",
                        (event.event_id, consumer.name, to_iso(self._clock())),
                    )
            # Frontera de entrega: cualquier fallo del consumidor se guarda y se reintenta.
            except Exception as exc:  # noqa: BLE001
                return consumer.name, exc
        return None

    def _delivered_to(self, event_id: str, consumer: str) -> bool:
        rows = self._database.fetchall(
            "SELECT 1 FROM event_deliveries WHERE event_id = ? AND consumer = ?",
            (event_id, consumer),
        )
        return bool(rows)

    def _record_failure(self, event_id: str, failure: tuple[str, Exception]) -> str:
        consumer, exc = failure
        message = f"{consumer}: {type(exc).__name__}: {str(exc)[:MAX_ERROR_LENGTH]}"
        rows = self._database.fetchall(
            "SELECT attempts FROM event_outbox WHERE event_id = ?", (event_id,)
        )
        attempts = int(rows[0][0]) + 1
        status = DEAD if attempts >= self._max_attempts else PENDING
        self._database.execute(
            "UPDATE event_outbox SET attempts = ?, last_error = ?, status = ? WHERE event_id = ?",
            (attempts, message, status, event_id),
        )
        return status


def _run_consumer(consumer: Consumer, event: Event, connection: sqlite3.Connection) -> None:
    """Ejecuta el consumidor bajo su autorizador y lo retira al terminar, incluso si falla."""
    connection.set_authorizer(_consumer_policy(bool(getattr(consumer, "writes_audit", False))))
    try:
        consumer.handle(event, connection)
    finally:
        connection.set_authorizer(None)


def _append(connection: sqlite3.Connection, event: Event) -> None:
    connection.execute(
        "INSERT INTO event_outbox (event_id, name, category, company_id, actor, occurred_at, "
        "payload) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            event.event_id,
            event.name,
            event.category.value,
            event.company_id,
            event.actor,
            event.occurred_at,
            json.dumps(event.payload, ensure_ascii=False, sort_keys=True),
        ),
    )


def _to_event(row: tuple[Any, ...]) -> Event:
    return Event(
        event_id=str(row[0]),
        name=str(row[1]),
        category=Category(str(row[2])),
        occurred_at=str(row[5]),
        company_id=None if row[3] is None else str(row[3]),
        actor=None if row[4] is None else str(row[4]),
        payload=dict(json.loads(str(row[6]))),
    )
