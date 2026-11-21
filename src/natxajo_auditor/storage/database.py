"""Acceso a la base de datos. Esta capa es la única que conoce sqlite3.

Otros motores podrían añadirse implementando los mismos métodos; hoy solo existe SQLite.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from natxajo_auditor.core.exceptions import StorageError


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._connection: sqlite3.Connection | None = None
        # None: no hay transacción abierta. Lista: callbacks pendientes de la transacción actual.
        self._after_commit: list[Callable[[], None]] | None = None

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
        """Transacción atómica: se confirma si todo va bien y se revierte si algo falla.

        Los callbacks de after_commit se ejecutan solo después de confirmar. Si la transacción
        se revierte, se descartan. Las transacciones anidadas no están admitidas.
        """
        if self._after_commit is not None:
            raise StorageError("las transacciones anidadas no están admitidas")
        connection = self.connection
        connection.execute("BEGIN IMMEDIATE")
        self._after_commit = []
        try:
            yield connection
        except BaseException:
            self._after_commit = None
            connection.execute("ROLLBACK")
            raise
        try:
            connection.execute("COMMIT")
        except BaseException:
            self._after_commit = None
            raise
        callbacks, self._after_commit = self._after_commit, None
        for callback in callbacks:
            callback()

    def snapshot(self, target: Path) -> None:
        """Copia consistente de la base con la API de copia de SQLite. No sobrescribe ningún archivo."""
        if self._after_commit is not None:
            raise StorageError("no se puede copiar la base dentro de una transacción")
        if target.exists():
            raise StorageError(f"la copia ya existe y no se sobrescribe: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        destination = sqlite3.connect(target)
        try:
            self.connection.backup(destination)
        except sqlite3.Error as exc:
            raise StorageError(f"No se pudo copiar la base de datos: {exc}") from exc
        finally:
            destination.close()

    def after_commit(self, callback: Callable[[], None]) -> None:
        """Ejecuta callback al confirmar la transacción actual, o de inmediato si no hay ninguna."""
        if self._after_commit is None:
            callback()
        else:
            self._after_commit.append(callback)

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
