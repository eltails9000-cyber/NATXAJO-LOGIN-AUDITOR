"""Ed25519 (RFC 8032) en Python puro, solo con la biblioteca estándar.

Se usa para firmar y verificar paquetes de plugins sin depender de paquetes externos. La
implementación se comprueba en tests contra vectores oficiales y contra firmas generadas con
OpenSSL.

Limitación: no es de tiempo constante. Es aceptable para verificar datos públicos, pero no debe
usarse para firmar secretos en un entorno donde un atacante pueda medir tiempos.
"""

from __future__ import annotations

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, P - 2, P)) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple[int, int, int, int]


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * _SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_BASE_Y = 4 * _inv(5) % P
_BASE_X = _recover_x(_BASE_Y, 0)
if _BASE_X is None:  # pragma: no cover - constante matemática, no depende de la entrada
    raise RuntimeError("punto base de Ed25519 no válido")
_B: Point = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % P)
_IDENTITY: Point = (0, 1, 1, 0)


def _add(p1: Point, p2: Point) -> Point:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * _D * t2 % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(scalar: int, point: Point) -> Point:
    result = _IDENTITY
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _equal(p1: Point, p2: Point) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _compress(point: Point) -> bytes:
    x, y, z, _ = point
    zinv = _inv(z)
    x_affine = x * zinv % P
    y_affine = y * zinv % P
    return (y_affine | ((x_affine & 1) << 255)).to_bytes(32, "little")


def _decompress(data: bytes) -> Point | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _hash_to_scalar(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % L


def _expand(secret: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(secret).digest()
    a = int.from_bytes(digest[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, digest[32:]


def _check_secret(secret: bytes) -> None:
    if len(secret) != 32:
        raise ValueError("la clave secreta Ed25519 debe tener 32 bytes")


def public_key(secret: bytes) -> bytes:
    """Clave pública (32 bytes) derivada de una semilla secreta de 32 bytes."""
    _check_secret(secret)
    a, _ = _expand(secret)
    return _compress(_mul(a, _B))


def sign(secret: bytes, message: bytes) -> bytes:
    """Firma determinista de 64 bytes."""
    _check_secret(secret)
    a, prefix = _expand(secret)
    pub = _compress(_mul(a, _B))
    r = _hash_to_scalar(prefix + message)
    r_point = _compress(_mul(r, _B))
    h = _hash_to_scalar(r_point + pub + message)
    s = (r + h * a) % L
    return r_point + s.to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True solo si la firma es válida. Nunca lanza excepciones por datos malformados."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a_point = _decompress(public)
    if a_point is None:
        return False
    r_bytes = signature[:32]
    r_point = _decompress(r_bytes)
    if r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = _hash_to_scalar(r_bytes + public + message)
    return _equal(_mul(s, _B), _add(r_point, _mul(h, a_point)))
