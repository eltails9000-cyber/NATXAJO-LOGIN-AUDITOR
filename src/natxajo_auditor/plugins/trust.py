"""Editores de confianza: claves públicas Ed25519 registradas y su nivel de confianza.

Niveles:
- official y verified: pueden habilitarse sin revisión adicional.
- third_party: requiere una revisión aprobada antes de habilitarse.
- revoked: ningún paquete firmado con esa clave se acepta ni se mantiene habilitado.

Esta clase solo lee. Las altas y las revocaciones son métodos internos (_insert, _revoke) que
PluginManager llama dentro de una transacción, después de que el guardián haya comprobado el
permiso, el ámbito y la confirmación. Las reglas de la base (clave inmutable, revocación final y
ningún borrado) están en la migración 9.
"""

from __future__ import annotations

import base64
import sqlite3
from dataclasses import dataclass
from typing import Any

from natxajo_auditor.core.exceptions import PluginError, ValidationError
from natxajo_auditor.core.validation import KEY_ID, require_text
from natxajo_auditor.storage.database import Database

OFFICIAL = "official"
VERIFIED = "verified"
THIRD_PARTY = "third_party"
REVOKED = "revoked"
TRUST_LEVELS: frozenset[str] = frozenset({OFFICIAL, VERIFIED, THIRD_PARTY})


@dataclass(frozen=True)
class Publisher:
    key_id: str
    display_name: str
    public_key: bytes
    trust_level: str


def requires_review(trust_level: str) -> bool:
    return trust_level == THIRD_PARTY


class TrustStore:
    def __init__(self, database: Database) -> None:
        self._database = database

    # Lectura pública

    def find(self, key_id: str) -> Publisher | None:
        rows = self._database.fetchall(
            "SELECT key_id, display_name, public_key, trust_level "
            "FROM plugin_publishers WHERE key_id = ?",
            (key_id,),
        )
        return _to_publisher(rows[0]) if rows else None

    def get_publisher(self, key_id: str) -> Publisher:
        publisher = self.find(key_id)
        if publisher is None:
            raise PluginError(f"editor no registrado: {key_id}")
        return publisher

    def publishers(self) -> list[Publisher]:
        rows = self._database.fetchall(
            "SELECT key_id, display_name, public_key, trust_level "
            "FROM plugin_publishers ORDER BY key_id"
        )
        return [_to_publisher(row) for row in rows]

    # Escritura interna: solo PluginManager, dentro de una transacción autorizada.

    def _insert(
        self,
        connection: sqlite3.Connection,
        key_id: str,
        display_name: str,
        public_key: bytes,
        trust_level: str,
    ) -> None:
        if not KEY_ID.match(key_id):
            raise ValidationError(f"identificador de editor no válido: {key_id}")
        require_text(display_name, "nombre", "editor")
        if len(public_key) != 32:
            raise ValidationError("la clave pública Ed25519 debe tener 32 bytes")
        if trust_level not in TRUST_LEVELS:
            raise ValidationError(
                f"nivel de confianza no válido: {trust_level} "
                f"(use: {', '.join(sorted(TRUST_LEVELS))})"
            )
        # La comprobación y la escritura van en la misma transacción: dos altas simultáneas con
        # la misma clave no pueden confirmarse las dos.
        if connection.execute(
            "SELECT 1 FROM plugin_publishers WHERE key_id = ?", (key_id,)
        ).fetchone():
            raise PluginError(f"el editor ya está registrado: {key_id}")
        connection.execute(
            "INSERT INTO plugin_publishers (key_id, display_name, public_key, trust_level) "
            "VALUES (?, ?, ?, ?)",
            (key_id, display_name, base64.b64encode(public_key).decode("ascii"), trust_level),
        )

    def _revoke(self, connection: sqlite3.Connection, key_id: str) -> None:
        publisher = self.get_publisher(key_id)
        if publisher.trust_level == REVOKED:
            raise PluginError(f"el editor ya está revocado: {key_id}")
        connection.execute(
            "UPDATE plugin_publishers SET trust_level = ?, updated_at = CURRENT_TIMESTAMP "
            "WHERE key_id = ?",
            (REVOKED, key_id),
        )


def _to_publisher(row: tuple[Any, ...]) -> Publisher:
    return Publisher(
        key_id=str(row[0]),
        display_name=str(row[1]),
        public_key=base64.b64decode(str(row[2])),
        trust_level=str(row[3]),
    )
