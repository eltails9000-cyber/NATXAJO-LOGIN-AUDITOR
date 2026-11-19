import sqlite3
from pathlib import Path


class DatabaseManager:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection: sqlite3.Connection | None = None

    def initialize(self) -> None:
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS platform_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        self.connection.commit()

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
