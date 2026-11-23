"""Diagnóstico general de la plataforma: cada comprobación devuelve un estado y un detalle legible.

Las comprobaciones son de solo lectura. No reparan nada: indican qué revisar. Estados:
- ok: sin incidencias.
- aviso: el sistema funciona, pero hay algo pendiente o una capacidad no disponible.
- error: algo impide operar con seguridad (base de datos dañada, copias alteradas, carpeta no
  escribible).
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from natxajo_auditor.maintenance.cleanup import temp_files
from natxajo_auditor.storage.backups import BackupManager
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.migrations import MIN_SQLITE_DROP_COLUMN, pending_versions
from natxajo_auditor.storage.outbox import EventOutbox

MIN_PYTHON: tuple[int, int] = (3, 11)


class Status(StrEnum):
    OK = "ok"
    AVISO = "aviso"
    ERROR = "error"


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    detail: str


def overall(checks: Sequence[Check]) -> Status:
    if any(check.status is Status.ERROR for check in checks):
        return Status.ERROR
    if any(check.status is Status.AVISO for check in checks):
        return Status.AVISO
    return Status.OK


def collect_checks(
    *,
    database: Database,
    outbox: EventOutbox,
    backups: BackupManager,
    managed_dirs: Sequence[Path],
    python_version: tuple[int, int, int],
    sqlite_version: tuple[int, int, int],
) -> list[Check]:
    return [
        _python(python_version),
        _sqlite(sqlite_version),
        _database(database),
        _migrations(database),
        _outbox(outbox),
        _backups(backups),
        _temp_files(managed_dirs),
        _writable(managed_dirs),
    ]


def _python(version: tuple[int, int, int]) -> Check:
    text = ".".join(str(part) for part in version)
    if version[:2] < MIN_PYTHON:
        return Check("python", Status.ERROR, f"Python {text}; se requiere 3.11 o posterior")
    return Check("python", Status.OK, f"Python {text}")


def _sqlite(version: tuple[int, int, int]) -> Check:
    text = ".".join(str(part) for part in version)
    needed = ".".join(str(part) for part in MIN_SQLITE_DROP_COLUMN)
    if version < MIN_SQLITE_DROP_COLUMN:
        return Check(
            "sqlite",
            Status.AVISO,
            f"SQLite {text}; revertir las migraciones 6 y 8 requiere {needed} o posterior",
        )
    return Check("sqlite", Status.OK, f"SQLite {text}")


def _database(database: Database) -> Check:
    rows = database.fetchall("PRAGMA integrity_check")
    messages = [str(row[0]) for row in rows]
    if messages == ["ok"]:
        return Check("base_de_datos", Status.OK, "integridad verificada")
    return Check("base_de_datos", Status.ERROR, f"integridad: {messages[0][:160]}")


def _migrations(database: Database) -> Check:
    pending = pending_versions(database)
    if pending:
        return Check("migraciones", Status.AVISO, f"pendientes: {pending}")
    return Check("migraciones", Status.OK, "todas aplicadas")


def _outbox(outbox: EventOutbox) -> Check:
    dead = outbox.dead_events()
    pending = outbox.pending_count()
    if dead:
        return Check(
            "eventos",
            Status.AVISO,
            f"{len(dead)} evento(s) fallido(s); pendientes de entrega: {pending}",
        )
    return Check("eventos", Status.OK, f"pendientes de entrega: {pending}")


def _backups(backups: BackupManager) -> Check:
    report = backups.integrity()
    problems = report.get("problems")
    count = len(backups.backups())
    if report.get("status") == "healthy":
        return Check("copias", Status.OK, f"{count} copia(s) verificadas")
    found = len(problems) if isinstance(problems, list) else 1
    return Check("copias", Status.ERROR, f"{found} problema(s) con las copias")


def _temp_files(managed_dirs: Iterable[Path]) -> Check:
    count = len(temp_files(managed_dirs))
    if count:
        return Check(
            "temporales",
            Status.AVISO,
            f"{count} archivo(s) temporal(es); límpielos desde mantenimiento",
        )
    return Check("temporales", Status.OK, "sin temporales")


def _writable(managed_dirs: Iterable[Path]) -> Check:
    blocked = [
        str(directory)
        for directory in managed_dirs
        if directory.is_dir() and not os.access(directory, os.W_OK)
    ]
    if blocked:
        return Check("escritura", Status.ERROR, f"carpetas no escribibles: {len(blocked)}")
    return Check("escritura", Status.OK, "carpetas escribibles")
