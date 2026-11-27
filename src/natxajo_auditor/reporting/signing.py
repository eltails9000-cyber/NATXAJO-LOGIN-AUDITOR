"""Firma de informes con Ed25519.

La clave privada de la instalación vive en la carpeta de almacenamiento. Se crea una sola vez, con
permisos 0600 en sistemas POSIX (en Windows esos permisos no se aplican). Nunca se sobrescribe: si
el archivo existe, se usa tal cual. Cada informe exportado recibe un archivo `.firma.json` junto a
él con el algoritmo, la clave pública y la firma.

Al verificar, la clave de confianza es la de la instalación, no la que venga en el archivo de
firma. Un informe con firma de otra clave no es válido aunque la firma verifique.

Un hash guardado junto al archivo no es una firma. Solo cuenta como firmado un informe cuya firma
verifica con la clave de la instalación. Los informes anteriores a esta función no tienen archivo
de firma y se muestran como `sin_firma`.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Final

from natxajo_auditor.core import ed25519
from natxajo_auditor.core.exceptions import StorageError

ALGORITHM: Final = "Ed25519"
KEY_FILE: Final = "firma_informes.clave"
SIGNATURE_SUFFIX: Final = ".firma.json"
SIGNED: Final = "firmado_valido"
UNSIGNED: Final = "sin_firma"
INVALID: Final = "firma_no_valida"
UNREADABLE: Final = "no_legible"


def signature_path(report: Path) -> Path:
    return report.with_name(report.name + SIGNATURE_SUFFIX)


class ReportSigner:
    def __init__(self, key_path: Path) -> None:
        self._key_path = key_path
        self._secret: bytes | None = None
        self._public: bytes | None = None

    def sign(self, content: bytes) -> dict[str, str]:
        """Firma el contenido. Crea la clave de la instalación si todavía no existe."""
        secret = self._load_or_create()
        public = self._public_of(secret)
        return {
            "algoritmo": ALGORITHM,
            "clave_publica": public.hex(),
            "firma": ed25519.sign(secret, content).hex(),
        }

    def check(self, report: Path) -> str:
        """Estado de la firma de un informe. Nunca crea claves ni modifica archivos."""
        sidecar = signature_path(report)
        if not sidecar.exists():
            return UNSIGNED
        try:
            data = json.loads(sidecar.read_text(encoding="utf-8"))
            algorithm = data["algoritmo"]
            public = bytes.fromhex(str(data["clave_publica"]))
            signature = bytes.fromhex(str(data["firma"]))
        except (OSError, ValueError, KeyError, TypeError):
            return UNREADABLE
        if algorithm != ALGORITHM:
            return INVALID
        trusted = self._trusted_public()
        if trusted is None or public != trusted:
            return INVALID
        try:
            content = report.read_bytes()
        except OSError:
            return UNREADABLE
        return SIGNED if ed25519.verify(trusted, content, signature) else INVALID

    def _trusted_public(self) -> bytes | None:
        if self._public is None:
            if not self._key_path.exists():
                return None
            self._public = self._public_of(self._load_or_create())
        return self._public

    def _load_or_create(self) -> bytes:
        if self._secret is not None:
            return self._secret
        if self._key_path.exists():
            try:
                secret = bytes.fromhex(self._key_path.read_text(encoding="ascii").strip())
            except (OSError, ValueError) as exc:
                raise StorageError("la clave de firma de informes no es legible") from exc
            if len(secret) != 32:
                raise StorageError("la clave de firma de informes no tiene el tamaño esperado")
        else:
            secret = secrets.token_bytes(32)
            _write_private(self._key_path, secret.hex())
        self._secret = secret
        return secret

    def _public_of(self, secret: bytes) -> bytes:
        public = ed25519.public_key(secret)
        self._public = public
        return public


def _write_private(path: Path, text: str) -> None:
    """Crea el archivo de clave sin sobrescribir ninguno y con permisos restringidos."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
