"""Documento de configuración de autenticación: esquema cerrado, validación y huella.

El documento describe cómo está configurado un sistema de autenticación (políticas de contraseña,
bloqueo, sesiones, cookies, transporte, doble factor y control de frecuencia). Es un archivo que
prepara el responsable del sistema. La plataforma no lo obtiene del objetivo.

El esquema es una lista cerrada de campos. No existe ningún campo para contraseñas, fichas de
sesión ni otros secretos, así que un documento no puede transportarlos: cualquier clave que no
esté en el esquema se rechaza. Los mensajes de error indican la sección y el campo, pero nunca el
valor recibido ni el nombre de una clave desconocida.

Un campo con valor null significa "declarado sin configurar". Un campo ausente significa "no
declarado" y la regla correspondiente queda no evaluable.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.utilities import sha256_bytes

SCHEMA_VERSION: Final = 1
MAX_DOCUMENT_BYTES: Final = 256 * 1024

Scalar = str | int | bool | None

_INT = "entero"
_BOOL = "booleano"
_TEXT = "texto"


@dataclass(frozen=True)
class FieldSpec:
    kind: str
    minimum: int | None = None
    maximum: int | None = None
    choices: frozenset[str] = field(default_factory=frozenset)


_HASH_CHOICES = frozenset(
    {"argon2id", "bcrypt", "scrypt", "pbkdf2-sha256", "pbkdf2-sha1", "sha256", "sha1", "md5"}
)

SCHEMA: Mapping[str, Mapping[str, FieldSpec]] = {
    "contrasenas": {
        "longitud_minima": FieldSpec(_INT, 1, 256),
        "complejidad": FieldSpec(_BOOL),
        "algoritmo": FieldSpec(_TEXT, choices=_HASH_CHOICES),
    },
    "bloqueo": {
        "intentos_maximos": FieldSpec(_INT, 0, 1000),
        "duracion_minutos": FieldSpec(_INT, 0, 100000),
        "mensaje_generico": FieldSpec(_BOOL),
    },
    "sesiones": {
        "inactividad_minutos": FieldSpec(_INT, 1, 10080),
        "absoluta_horas": FieldSpec(_INT, 1, 8760),
        "simultaneas_maximas": FieldSpec(_INT, 1, 1000),
    },
    "cookies": {
        "secure": FieldSpec(_BOOL),
        "http_only": FieldSpec(_BOOL),
        "same_site": FieldSpec(_TEXT, choices=frozenset({"Strict", "Lax", "None"})),
    },
    "transporte": {
        "tls_minimo": FieldSpec(_TEXT, choices=frozenset({"1.0", "1.1", "1.2", "1.3"})),
        "hsts": FieldSpec(_BOOL),
    },
    "mfa": {"administradores_obligatorio": FieldSpec(_BOOL)},
    "frecuencia": {
        "habilitado": FieldSpec(_BOOL),
        "solicitudes_por_minuto": FieldSpec(_INT, 1, 100000),
    },
}


@dataclass(frozen=True)
class Snapshot:
    """Campos declarados de un documento validado. Solo contiene escalares."""

    values: Mapping[tuple[str, str], Scalar]

    def has(self, section: str, name: str) -> bool:
        return (section, name) in self.values

    def value(self, section: str, name: str) -> Scalar:
        return self.values[(section, name)]

    def canonical_sha256(self) -> str:
        """Huella del contenido declarado. No depende del orden ni del espaciado del archivo."""
        content = {
            f"{section}.{name}": value for (section, name), value in sorted(self.values.items())
        }
        text = json.dumps(
            {"esquema": SCHEMA_VERSION, "valores": content},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return sha256_bytes(text.encode("utf-8"))


def parse_snapshot(document: object) -> Snapshot:
    """Valida un documento ya decodificado y devuelve sus campos declarados."""
    if not isinstance(document, dict):
        raise ValidationError("el documento de configuración debe ser un objeto JSON")
    unknown_root = set(document) - set(SCHEMA) - {"esquema"}
    if unknown_root:
        raise ValidationError(
            f"el documento tiene {len(unknown_root)} clave(s) no admitida(s) en el nivel raíz"
        )
    if document.get("esquema") != SCHEMA_VERSION or isinstance(document.get("esquema"), bool):
        raise ValidationError(f"el campo 'esquema' debe valer {SCHEMA_VERSION}")

    values: dict[tuple[str, str], Scalar] = {}
    for section, fields in SCHEMA.items():
        if section not in document:
            continue
        block = document[section]
        if not isinstance(block, dict):
            raise ValidationError(f"la sección '{section}' debe ser un objeto JSON")
        unknown = set(block) - set(fields)
        if unknown:
            raise ValidationError(
                f"la sección '{section}' tiene {len(unknown)} clave(s) no admitida(s)"
            )
        for name, raw in block.items():
            values[(section, name)] = _validate(section, name, raw, fields[name])
    return Snapshot(values=values)


def _validate(section: str, name: str, raw: object, spec: FieldSpec) -> Scalar:
    where = f"{section}.{name}"
    if raw is None:
        return None
    if spec.kind == _BOOL:
        if not isinstance(raw, bool):
            raise ValidationError(f"{where}: se esperaba true, false o null")
        return raw
    if spec.kind == _INT:
        if not isinstance(raw, int) or isinstance(raw, bool):
            raise ValidationError(f"{where}: se esperaba un entero o null")
        low = spec.minimum if spec.minimum is not None else raw
        high = spec.maximum if spec.maximum is not None else raw
        if not low <= raw <= high:
            raise ValidationError(f"{where}: el entero debe estar entre {low} y {high}")
        return raw
    if not isinstance(raw, str) or raw not in spec.choices:
        options = ", ".join(sorted(spec.choices))
        raise ValidationError(f"{where}: se esperaba uno de [{options}] o null")
    return raw


def decode_document(text: str) -> object:
    """Decodifica JSON estricto: sin constantes NaN/Infinity y sin claves repetidas."""

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValidationError("el documento repite una clave")
            result[key] = value
        return result

    def reject_constant(name: str) -> object:
        raise ValidationError("el documento contiene un número no admitido")

    try:
        return json.loads(text, object_pairs_hook=reject_duplicates, parse_constant=reject_constant)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"JSON no válido (línea {exc.lineno}, columna {exc.colno})") from None
    except RecursionError:
        raise ValidationError("el documento está anidado en exceso") from None
