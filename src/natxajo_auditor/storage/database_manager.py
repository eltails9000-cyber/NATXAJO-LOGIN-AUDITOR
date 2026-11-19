import sqlite3
from pathlib import Path

from natxajo_auditor.storage.migrations import MigrationManager


class DatabaseManager:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection: sqlite3.Connection | None = None

    def initialize(self) -> None:
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("PRAGMA foreign_keys = ON")
        MigrationManager(self.connection).initialize()

    def execute(self, statement: str, parameters: tuple[object, ...] = ()) -> sqlite3.Cursor:
        if self.connection is None:
            raise RuntimeError("La base de datos no está inicializada")
        cursor = self.connection.execute(statement, parameters)
        self.connection.commit()
        return cursor

    def close(self) -> None:
        if self.connection:
            self.connection.close()
            self.connection = None
