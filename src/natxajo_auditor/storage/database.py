"""Acceso a la base de datos. Esta capa es la única que conoce sqlite3.

Otros motores podrían añadirse implementando los mismos métodos; hoy solo existe SQLite.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from natxajo_auditor.core.exceptions import StorageError


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._connection: sqlite3.Connection | None = None

    def open(self) -> None:
        if self._connection is not None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Modo autocommit: las transacciones se abren explícitamente con transaction().
            connection = sqlite3.connect(self.path, isolation_level=None)
            connection.execute("PRAGMA foreign_keys = ON")
        except (OSError, sqlite3.Error) as exc:
            raise StorageError(f"No se pudo abrir la base de datos: {exc}") from exc
        self._connection = connection

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise StorageError("La base de datos no está abierta")
        return self._connection

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        try:
            self.connection.execute(sql, tuple(params))
        except sqlite3.Error as exc:
            raise StorageError(f"Error de base de datos: {exc}") from exc

    def fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
        try:
            return list(self.connection.execute(sql, tuple(params)).fetchall())
        except sqlite3.Error as exc:
            raise StorageError(f"Error de base de datos: {exc}") from exc

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Transacción atómica: se confirma si todo va bien y se revierte si algo falla."""
        connection = self.connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        else:
            connection.execute("COMMIT")

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
