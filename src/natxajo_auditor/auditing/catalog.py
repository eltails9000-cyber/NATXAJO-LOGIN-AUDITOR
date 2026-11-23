"""Catálogo de reglas de auditoría y perfiles de evaluación.

Cada regla compara un valor declarado en el documento de configuración con un mínimo, un máximo,
un rango, una lista de valores aceptados o un interruptor. Las reglas son datos: no leen la red,
no contactan con ningún objetivo y no ejecutan código.

Una regla de umbral puede ajustarse dentro de límites fijos (`overridable`). Los límites impiden
que una sobrescritura afloje un control hasta un valor inseguro. Las reglas de rango no admiten
sobrescritura.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from natxajo_auditor.core.exceptions import ValidationError


class Severity(StrEnum):
    BAJO = "bajo"
    MEDIO = "medio"
    ALTO = "alto"
    CRITICO = "critico"


SEVERITY_RANK: Mapping[Severity, int] = {
    Severity.BAJO: 1,
    Severity.MEDIO: 2,
    Severity.ALTO: 3,
    Severity.CRITICO: 4,
}


class Status(StrEnum):
    """CUMPLE y NO_CUMPLE son juicios. NO_EVALUABLE significa que el documento no declara el campo."""

    CUMPLE = "cumple"
    NO_CUMPLE = "no_cumple"
    NO_EVALUABLE = "no_evaluable"


class Operator(StrEnum):
    AT_LEAST = "minimo"
    AT_MOST = "maximo"
    RANGE = "rango"
    IS_TRUE = "verdadero"
    ONE_OF = "uno_de"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    section: str
    field: str
    operator: Operator
    severity: Severity
    recommendation: str
    minimum: int | None = None
    maximum: int | None = None
    allowed: frozenset[str] = frozenset()
    overridable: tuple[int, int] | None = None

    def __post_init__(self) -> None:
        self._check_shape()
        if self.overridable is not None:
            low, high = self.overridable
            current = self.minimum if self.operator is Operator.AT_LEAST else self.maximum
            if not (low <= (current or 0) <= high) or low > high:
                raise ValidationError(f"{self.id}: el umbral por defecto está fuera de sus límites")

    def _check_shape(self) -> None:
        if self.operator is Operator.AT_LEAST and (
            self.minimum is None or self.maximum is not None
        ):
            raise ValidationError(f"{self.id}: una regla de mínimo necesita solo 'minimum'")
        if self.operator is Operator.AT_MOST and (self.maximum is None or self.minimum is not None):
            raise ValidationError(f"{self.id}: una regla de máximo necesita solo 'maximum'")
        if self.operator is Operator.RANGE:
            if self.minimum is None or self.maximum is None or self.minimum > self.maximum:
                raise ValidationError(f"{self.id}: una regla de rango necesita límites ordenados")
            if self.overridable is not None:
                raise ValidationError(f"{self.id}: una regla de rango no admite sobrescritura")
        if self.operator is Operator.ONE_OF and not self.allowed:
            raise ValidationError(f"{self.id}: una regla de lista necesita valores aceptados")
        if self.operator is Operator.IS_TRUE and (
            self.minimum is not None or self.maximum is not None or self.allowed
        ):
            raise ValidationError(f"{self.id}: una regla de interruptor no lleva umbrales")
        if self.overridable is not None and self.operator not in (
            Operator.AT_LEAST,
            Operator.AT_MOST,
        ):
            raise ValidationError(
                f"{self.id}: solo las reglas de mínimo o máximo son sobrescribibles"
            )

    @property
    def path(self) -> str:
        return f"{self.section}.{self.field}"

    @property
    def expected(self) -> str:
        """Texto que describe el valor que la regla exige. Se guarda con cada evaluación."""
        if self.operator is Operator.AT_LEAST:
            return f"al menos {self.minimum}"
        if self.operator is Operator.AT_MOST:
            return f"como máximo {self.maximum}"
        if self.operator is Operator.RANGE:
            return f"entre {self.minimum} y {self.maximum}"
        if self.operator is Operator.IS_TRUE:
            return "activado (true)"
        return "uno de: " + ", ".join(sorted(self.allowed))


_HASH_ALGORITHMS = frozenset({"argon2id", "bcrypt", "scrypt", "pbkdf2-sha256"})

BUILTIN_RULES: tuple[Rule, ...] = (
    Rule(
        id="AUT-001",
        title="Longitud mínima de contraseña",
        section="contrasenas",
        field="longitud_minima",
        operator=Operator.AT_LEAST,
        minimum=12,
        overridable=(8, 128),
        severity=Severity.ALTO,
        recommendation=(
            "Exija al menos 12 caracteres y compruebe las contraseñas nuevas contra listas "
            "de contraseñas filtradas."
        ),
    ),
    Rule(
        id="AUT-002",
        title="Requisitos de complejidad de contraseña",
        section="contrasenas",
        field="complejidad",
        operator=Operator.IS_TRUE,
        severity=Severity.MEDIO,
        recommendation=(
            "Impida contraseñas triviales. Prefiera la longitud a las reglas de composición."
        ),
    ),
    Rule(
        id="AUT-003",
        title="Algoritmo de almacenamiento de contraseñas",
        section="contrasenas",
        field="algoritmo",
        operator=Operator.ONE_OF,
        allowed=_HASH_ALGORITHMS,
        severity=Severity.CRITICO,
        recommendation=(
            "Guarde las contraseñas con argon2id, bcrypt, scrypt o PBKDF2-HMAC-SHA256. "
            "Nunca use hashes rápidos ni texto plano."
        ),
    ),
    Rule(
        id="AUT-004",
        title="Bloqueo tras intentos fallidos",
        section="bloqueo",
        field="intentos_maximos",
        operator=Operator.RANGE,
        minimum=1,
        maximum=10,
        severity=Severity.MEDIO,
        recommendation=(
            "Bloquee temporalmente la cuenta tras un número limitado de fallos, entre 1 y 10. "
            "El valor 0 desactiva el bloqueo."
        ),
    ),
    Rule(
        id="AUT-005",
        title="Duración del bloqueo temporal",
        section="bloqueo",
        field="duracion_minutos",
        operator=Operator.AT_LEAST,
        minimum=5,
        overridable=(1, 1440),
        severity=Severity.MEDIO,
        recommendation="Mantenga el bloqueo al menos el tiempo que fije su política.",
    ),
    Rule(
        id="AUT-006",
        title="Mensaje genérico durante el bloqueo",
        section="bloqueo",
        field="mensaje_generico",
        operator=Operator.IS_TRUE,
        severity=Severity.ALTO,
        recommendation=(
            "Responda igual exista o no la cuenta, para no permitir enumerar usuarios."
        ),
    ),
    Rule(
        id="AUT-007",
        title="Caducidad de sesión por inactividad",
        section="sesiones",
        field="inactividad_minutos",
        operator=Operator.AT_MOST,
        maximum=15,
        overridable=(1, 240),
        severity=Severity.MEDIO,
        recommendation="Cierre las sesiones inactivas en un plazo corto.",
    ),
    Rule(
        id="AUT-008",
        title="Caducidad absoluta de sesión",
        section="sesiones",
        field="absoluta_horas",
        operator=Operator.AT_MOST,
        maximum=8,
        overridable=(1, 168),
        severity=Severity.MEDIO,
        recommendation="Obligue a iniciar sesión de nuevo tras un plazo absoluto.",
    ),
    Rule(
        id="AUT-009",
        title="Sesiones simultáneas por cuenta",
        section="sesiones",
        field="simultaneas_maximas",
        operator=Operator.RANGE,
        minimum=1,
        maximum=5,
        severity=Severity.BAJO,
        recommendation="Limite el número de sesiones simultáneas por cuenta.",
    ),
    Rule(
        id="AUT-010",
        title="Cookies de sesión solo por HTTPS",
        section="cookies",
        field="secure",
        operator=Operator.IS_TRUE,
        severity=Severity.ALTO,
        recommendation="Marque las cookies de sesión con el atributo Secure.",
    ),
    Rule(
        id="AUT-011",
        title="Cookies de sesión sin acceso desde scripts",
        section="cookies",
        field="http_only",
        operator=Operator.IS_TRUE,
        severity=Severity.ALTO,
        recommendation="Marque las cookies de sesión con el atributo HttpOnly.",
    ),
    Rule(
        id="AUT-012",
        title="Atributo SameSite de las cookies",
        section="cookies",
        field="same_site",
        operator=Operator.ONE_OF,
        allowed=frozenset({"Lax", "Strict"}),
        severity=Severity.MEDIO,
        recommendation="Use SameSite=Lax o SameSite=Strict en las cookies de sesión.",
    ),
    Rule(
        id="AUT-013",
        title="Versión mínima de TLS",
        section="transporte",
        field="tls_minimo",
        operator=Operator.ONE_OF,
        allowed=frozenset({"1.2", "1.3"}),
        severity=Severity.ALTO,
        recommendation="Desactive TLS 1.0 y 1.1. Use TLS 1.2 como mínimo.",
    ),
    Rule(
        id="AUT-014",
        title="Cabecera HSTS",
        section="transporte",
        field="hsts",
        operator=Operator.IS_TRUE,
        severity=Severity.MEDIO,
        recommendation=("Envíe Strict-Transport-Security para impedir la degradación a HTTP."),
    ),
    Rule(
        id="AUT-015",
        title="Segundo factor para administradores",
        section="mfa",
        field="administradores_obligatorio",
        operator=Operator.IS_TRUE,
        severity=Severity.ALTO,
        recommendation="Exija un segundo factor a las cuentas con privilegios.",
    ),
    Rule(
        id="AUT-016",
        title="Control de frecuencia de intentos",
        section="frecuencia",
        field="habilitado",
        operator=Operator.IS_TRUE,
        severity=Severity.ALTO,
        recommendation=(
            "Active un control de frecuencia en el punto de autenticación. Revíselo con cuentas "
            "de laboratorio autorizadas y sin intentar eludirlo."
        ),
    ),
    Rule(
        id="AUT-017",
        title="Límite de solicitudes de autenticación por minuto",
        section="frecuencia",
        field="solicitudes_por_minuto",
        operator=Operator.AT_MOST,
        maximum=60,
        overridable=(1, 10000),
        severity=Severity.BAJO,
        recommendation="Establezca un límite conservador de solicitudes por minuto.",
    ),
)

RULES_BY_ID: Mapping[str, Rule] = {rule.id: rule for rule in BUILTIN_RULES}
if len(RULES_BY_ID) != len(BUILTIN_RULES):
    raise ValidationError("el catálogo de reglas tiene identificadores repetidos")

# Perfil -> gravedad mínima de las reglas que incluye. "completo" incluye todas.
PROFILE_MIN_SEVERITY: Mapping[str, Severity] = {
    "completo": Severity.BAJO,
    "critico": Severity.ALTO,
}


def apply_override(rule: Rule, value: object) -> Rule:
    """Devuelve la regla con su umbral sustituido, si la regla lo admite y el valor está en límites."""
    if rule.overridable is None:
        raise ValidationError(f"{rule.id} no admite un umbral configurable")
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{rule.id}: el umbral debe ser un entero")
    low, high = rule.overridable
    if not low <= value <= high:
        raise ValidationError(f"{rule.id}: el umbral debe estar entre {low} y {high}")
    if rule.operator is Operator.AT_LEAST:
        return dataclasses.replace(rule, minimum=value)
    return dataclasses.replace(rule, maximum=value)
