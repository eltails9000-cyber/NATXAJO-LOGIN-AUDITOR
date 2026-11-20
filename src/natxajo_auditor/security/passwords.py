"""Contraseñas: PBKDF2-HMAC-SHA256 con sal aleatoria. Nunca se guardan en claro.

El formato guardado incluye el número de iteraciones. Así una contraseña registrada con un coste
anterior sigue verificándose, y el coste puede subirse sin invalidar las cuentas existentes.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from natxajo_auditor.core.exceptions import ValidationError

ALGORITHM = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 600_000
MIN_ITERATIONS = 1_000
MIN_LENGTH = 12
MAX_LENGTH = 256
MIN_DISTINCT_CHARACTERS = 4
_SALT_BYTES = 16


def validate_policy(password: str, username: str) -> None:
    if not isinstance(password, str):
        raise ValidationError("la contraseña debe ser un texto")
    if len(password) < MIN_LENGTH:
        raise ValidationError(f"la contraseña debe tener al menos {MIN_LENGTH} caracteres")
    if len(password) > MAX_LENGTH:
        raise ValidationError(f"la contraseña no puede tener más de {MAX_LENGTH} caracteres")
    if not password.strip():
        raise ValidationError("la contraseña no puede estar formada solo por espacios")
    if len(set(password)) < MIN_DISTINCT_CHARACTERS:
        raise ValidationError("la contraseña tiene muy pocos caracteres distintos")
    if password.lower() == username.lower():
        raise ValidationError("la contraseña no puede ser igual al nombre de usuario")


def hash_password(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    if iterations < MIN_ITERATIONS:
        raise ValueError(f"el número de iteraciones debe ser al menos {MIN_ITERATIONS}")
    salt = os.urandom(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{ALGORITHM}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """True solo si la contraseña coincide. Un registro malformado devuelve False."""
    try:
        algorithm, iterations_text, salt_hex, digest_hex = stored.split("$")
        iterations = int(iterations_text)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    if algorithm != ALGORITHM or iterations < MIN_ITERATIONS:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)
