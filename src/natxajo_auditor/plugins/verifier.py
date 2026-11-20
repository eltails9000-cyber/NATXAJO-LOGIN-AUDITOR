"""Verificación completa de un paquete de plugin antes de aceptarlo.

Orden: archivos obligatorios, firma y editor, integridad de cada archivo, manifiesto, versión de
API y compatibilidad con el núcleo. Cualquier fallo se informa con su motivo.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from pathlib import Path

from natxajo_auditor.core import ed25519
from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.utilities import sha256_bytes
from natxajo_auditor.core.validation import require_text
from natxajo_auditor.plugins.api import check_api_version
from natxajo_auditor.plugins.manifest import PLUGIN_FILE, PluginManifest, load_plugin_manifest
from natxajo_auditor.plugins.package import (
    INTEGRITY_FILE,
    INTEGRITY_FORMAT,
    SIGNATURE_FILE,
    verify_files,
)
from natxajo_auditor.plugins.trust import REVOKED, TrustStore
from natxajo_auditor.versioning.manifest import kernel_matches


@dataclass(frozen=True)
class VerifiedPackage:
    manifest: PluginManifest
    publisher_key_id: str
    trust_level: str
    integrity_sha256: str


def verify_package(root: Path, trust: TrustStore, kernel_version: str) -> VerifiedPackage:
    if not root.is_dir():
        raise ValidationError(f"no existe el paquete: {root}")
    for name in (PLUGIN_FILE, INTEGRITY_FILE, SIGNATURE_FILE):
        if not (root / name).is_file():
            raise ValidationError(f"el paquete no contiene {name}")

    integrity_bytes = (root / INTEGRITY_FILE).read_bytes()
    key_id, signature = _read_signature(root / SIGNATURE_FILE)
    publisher = trust.find(key_id)
    if publisher is None:
        raise ValidationError(f"editor no registrado: {key_id}")
    if publisher.trust_level == REVOKED:
        raise ValidationError(f"el editor {key_id} está revocado")
    if not ed25519.verify(publisher.public_key, integrity_bytes, signature):
        raise ValidationError(f"la firma no corresponde al editor {key_id}")

    expected = _read_integrity(integrity_bytes)
    if PLUGIN_FILE not in expected:
        raise ValidationError("integrity.json no cubre plugin.json")
    verify_files(root, expected)

    manifest = load_plugin_manifest(root / PLUGIN_FILE)
    check_api_version(manifest.api_version)
    if not kernel_matches(manifest.compatible_kernel, kernel_version):
        raise ValidationError(
            f"requiere núcleo {manifest.compatible_kernel}; el núcleo actual es {kernel_version}"
        )
    return VerifiedPackage(
        manifest=manifest,
        publisher_key_id=key_id,
        trust_level=publisher.trust_level,
        integrity_sha256=sha256_bytes(integrity_bytes),
    )


def _read_signature(path: Path) -> tuple[str, bytes]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{SIGNATURE_FILE} ilegible: {exc}") from exc
    if not isinstance(document, dict) or document.get("algorithm") != "ed25519":
        raise ValidationError("algoritmo de firma no soportado (se requiere ed25519)")
    key_id = require_text(document.get("key_id"), "key_id", SIGNATURE_FILE)
    encoded = require_text(document.get("signature"), "signature", SIGNATURE_FILE)
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("la firma no es base64 válido") from exc
    return key_id, signature


def _read_integrity(data: bytes) -> dict[str, str]:
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{INTEGRITY_FILE} ilegible: {exc}") from exc
    if not isinstance(document, dict) or document.get("format") != INTEGRITY_FORMAT:
        raise ValidationError(f"{INTEGRITY_FILE} con formato no soportado")
    files = document.get("files")
    if not isinstance(files, dict) or not all(
        isinstance(name, str) and isinstance(digest, str) for name, digest in files.items()
    ):
        raise ValidationError(f"{INTEGRITY_FILE} no contiene una lista válida de archivos")
    return {str(name): str(digest) for name, digest in files.items()}
