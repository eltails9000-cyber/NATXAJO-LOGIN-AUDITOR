"""Lectura del documento de configuración desde un archivo, con los límites necesarios.

- Solo archivos regulares. Un enlace simbólico no se sigue.
- Tamaño máximo fijo, para no cargar archivos enormes en memoria.
- UTF-8, admitiendo el BOM que añaden algunos editores de Windows.
- Los errores no repiten el contenido del archivo.
"""

from __future__ import annotations

from pathlib import Path

from natxajo_auditor.auditing.snapshot import MAX_DOCUMENT_BYTES, decode_document
from natxajo_auditor.core.exceptions import ValidationError


def read_document(path: Path, *, max_bytes: int = MAX_DOCUMENT_BYTES) -> object:
    """Devuelve el documento decodificado. La validación del esquema la hace snapshot.parse_snapshot."""
    if path.is_symlink():
        raise ValidationError("el documento no puede ser un enlace simbólico")
    if not path.is_file():
        raise ValidationError("el documento no existe o no es un archivo regular")
    size = path.stat().st_size
    if size > max_bytes:
        raise ValidationError(f"el documento supera el tamaño máximo de {max_bytes} bytes")
    try:
        text = path.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValidationError("el documento no está codificado en UTF-8") from None
    except OSError:
        raise ValidationError("no se pudo leer el documento") from None
    return decode_document(text)
