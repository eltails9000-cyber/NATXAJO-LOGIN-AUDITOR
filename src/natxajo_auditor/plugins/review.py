"""Revisión previa de paquetes: inventario de contenido y registro de decisiones.

El inventario es una heurística: clasifica archivos por extensión para que una persona los revise.
No detecta código malicioso y no sustituye la revisión humana ni el aislamiento de ejecución.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.validation import require_text
from natxajo_auditor.plugins.package import META_FILES, list_files
from natxajo_auditor.storage.database import Database

EXECUTABLE_SUFFIXES: frozenset[str] = frozenset(
    {
        ".py",
        ".pyw",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".sh",
        ".exe",
        ".dll",
        ".msi",
        ".jar",
    }
)
REVIEW_DECISIONS: frozenset[str] = frozenset({"approved", "rejected"})


@dataclass(frozen=True)
class InventoryItem:
    path: str
    kind: str


def inventory(root: Path) -> list[InventoryItem]:
    items: list[InventoryItem] = []
    for relative in sorted(list_files(root)):
        if relative in META_FILES:
            continue
        suffix = PurePosixPath(relative).suffix.lower()
        kind = "ejecutable" if suffix in EXECUTABLE_SUFFIXES else "datos"
        items.append(InventoryItem(relative, kind))
    return items


def needs_manual_review(items: list[InventoryItem]) -> bool:
    return any(item.kind == "ejecutable" for item in items)


class ReviewLog:
    def __init__(self, database: Database) -> None:
        self._database = database

    def record(
        self, plugin_id: str, version: str, reviewer: str, decision: str, findings: str
    ) -> None:
        if decision not in REVIEW_DECISIONS:
            raise ValidationError(f"decisión de revisión no válida: {decision}")
        require_text(reviewer, "revisor", "revisión")
        self._database.execute(
            "INSERT INTO plugin_reviews (plugin_id, version, reviewer, decision, findings) "
            "VALUES (?, ?, ?, ?, ?)",
            (plugin_id, version, reviewer, decision, findings),
        )

    def latest_decision(self, plugin_id: str, version: str) -> str | None:
        rows = self._database.fetchall(
            "SELECT decision FROM plugin_reviews WHERE plugin_id = ? AND version = ? "
            "ORDER BY id DESC LIMIT 1",
            (plugin_id, version),
        )
        return str(rows[0][0]) if rows else None

    def is_approved(self, plugin_id: str, version: str) -> bool:
        return self.latest_decision(plugin_id, version) == "approved"

    def history(self, plugin_id: str, version: str) -> list[dict[str, Any]]:
        rows = self._database.fetchall(
            "SELECT reviewer, decision, findings, created_at FROM plugin_reviews "
            "WHERE plugin_id = ? AND version = ? ORDER BY id",
            (plugin_id, version),
        )
        return [
            {"reviewer": row[0], "decision": row[1], "findings": row[2], "created_at": row[3]}
            for row in rows
        ]
