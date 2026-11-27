"""Concurrencia real del límite de sesiones.

Cada hilo abre su propia conexión a la misma base de datos y espera en una barrera, de modo que
los inicios se solapan de verdad. El recuento y la inserción de una sesión van en una misma
transacción de escritura: aunque lleguen a la vez, el límite por cuenta no puede superarse.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from natxajo_auditor.core.exceptions import SessionLimitError
from natxajo_auditor.core.utilities import utc_now
from natxajo_auditor.security.sessions import MAX_CONCURRENT_SESSIONS, SessionStore
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.migrations import apply_migrations

INTENTOS = 12


def _base(path: Path, usuarios: tuple[str, ...]) -> None:
    database = Database(path)
    database.open()
    try:
        apply_migrations(database)
        for usuario in usuarios:
            database.execute(
                "INSERT INTO accounts (username, password_hash, status) VALUES (?, 'hash', 'active')",
                (usuario,),
            )
    finally:
        database.close()


def _abrir_a_la_vez(path: Path, usuario: str, intentos: int) -> list[str]:
    """Lanza `intentos` inicios de sesión simultáneos, cada uno con su conexión."""
    barrera = threading.Barrier(intentos)

    def intento() -> str:
        database = Database(path)
        database.open()
        try:
            store = SessionStore(database, AuditLog(database), utc_now)
            barrera.wait()
            try:
                store.open(usuario)
            except SessionLimitError:
                return "rechazada"
            return "abierta"
        finally:
            database.close()

    with ThreadPoolExecutor(max_workers=intentos) as pool:
        futuros = [pool.submit(intento) for _ in range(intentos)]
        return [futuro.result() for futuro in futuros]


def _sesiones_vivas(path: Path, usuario: str) -> int:
    database = Database(path)
    database.open()
    try:
        rows = database.fetchall(
            "SELECT COUNT(*) FROM sessions WHERE username = ? AND revoked_at IS NULL",
            (usuario,),
        )
        return int(rows[0][0])
    finally:
        database.close()


def test_simultaneous_logins_never_exceed_the_account_limit(tmp_path: Path) -> None:
    path = tmp_path / "concurrencia.db"
    _base(path, ("cuenta_una",))

    resultados = _abrir_a_la_vez(path, "cuenta_una", INTENTOS)

    assert resultados.count("abierta") == MAX_CONCURRENT_SESSIONS
    assert resultados.count("rechazada") == INTENTOS - MAX_CONCURRENT_SESSIONS
    assert _sesiones_vivas(path, "cuenta_una") == MAX_CONCURRENT_SESSIONS


def test_each_refused_attempt_is_audited_once(tmp_path: Path) -> None:
    path = tmp_path / "auditoria.db"
    _base(path, ("cuenta_una",))

    resultados = _abrir_a_la_vez(path, "cuenta_una", INTENTOS)

    database = Database(path)
    database.open()
    try:
        rows = database.fetchall(
            "SELECT COUNT(*) FROM audit_events WHERE event_type = 'session.limit_reached'"
        )
    finally:
        database.close()
    assert int(rows[0][0]) == resultados.count("rechazada")


def test_the_limit_is_per_account_under_simultaneous_logins(tmp_path: Path) -> None:
    path = tmp_path / "dos_cuentas.db"
    _base(path, ("cuenta_una", "cuenta_dos"))

    primera = _abrir_a_la_vez(path, "cuenta_una", INTENTOS)
    segunda = _abrir_a_la_vez(path, "cuenta_dos", INTENTOS)

    assert primera.count("abierta") == MAX_CONCURRENT_SESSIONS
    assert segunda.count("abierta") == MAX_CONCURRENT_SESSIONS
    assert _sesiones_vivas(path, "cuenta_una") == MAX_CONCURRENT_SESSIONS
    assert _sesiones_vivas(path, "cuenta_dos") == MAX_CONCURRENT_SESSIONS
