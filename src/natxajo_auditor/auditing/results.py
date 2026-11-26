"""Resultados de una evaluación: modelo, validación de invariantes y registro para la terminal.

`validate_run` no confía en quien construyó el resultado. Recalcula cada estado a partir del valor
observado y de la regla efectiva del perfil. Así una fila alterada en la base de datos (un estado
cambiado, un hallazgo que sobra o falta) se detecta al cargarla.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from natxajo_auditor.auditing.catalog import PROFILE_MIN_SEVERITY, SEVERITY_RANK, Rule, Status
from natxajo_auditor.auditing.engine import Outcome, meets, resolve_rules
from natxajo_auditor.core.events import COMPANY_ID
from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.utilities import to_iso

RISK_NONE = "ninguno"
AUTHORIZATION_MIN = 3
AUTHORIZATION_MAX = 200
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class AuditRun:
    run_id: str
    company_id: str
    username: str
    profile: str
    overrides: Mapping[str, int]
    authorization_reference: str
    snapshot_sha256: str
    engine_version: str
    started_at: datetime
    finished_at: datetime
    outcomes: tuple[Outcome, ...]

    @property
    def passed(self) -> int:
        return sum(1 for outcome in self.outcomes if outcome.status is Status.CUMPLE)

    @property
    def failed(self) -> int:
        return sum(1 for outcome in self.outcomes if outcome.status is Status.NO_CUMPLE)

    @property
    def not_evaluable(self) -> int:
        return sum(1 for outcome in self.outcomes if outcome.status is Status.NO_EVALUABLE)

    @property
    def risk(self) -> str:
        """Gravedad más alta entre los incumplimientos, o `ninguno` si no hay ninguno."""
        failing = [
            outcome.severity for outcome in self.outcomes if outcome.status is Status.NO_CUMPLE
        ]
        if not failing:
            return RISK_NONE
        return max(failing, key=lambda severity: SEVERITY_RANK[severity]).value


def validate_run(run: AuditRun) -> None:
    """Comprueba los invariantes del resultado. Lanza ValidationError en el primer fallo."""
    _check_identity(run)
    if run.profile not in PROFILE_MIN_SEVERITY:
        raise ValidationError("el perfil de la evaluación no existe")
    if not AUTHORIZATION_MIN <= len(run.authorization_reference) <= AUTHORIZATION_MAX:
        raise ValidationError("la referencia de autorización no tiene una longitud válida")
    if not run.authorization_reference.isprintable():
        raise ValidationError("la referencia de autorización contiene caracteres no imprimibles")
    if not _SHA256.fullmatch(run.snapshot_sha256):
        raise ValidationError("la huella del documento no es un SHA-256")
    if not run.engine_version.strip():
        raise ValidationError("la evaluación no declara la versión del motor")
    if run.finished_at < run.started_at:
        raise ValidationError("la evaluación termina antes de empezar")

    expected_rules = {rule.id: rule for rule in resolve_rules(run.profile, run.overrides)}
    seen: set[str] = set()
    for outcome in run.outcomes:
        if outcome.rule_id in seen:
            raise ValidationError(f"hallazgo repetido: {outcome.rule_id}")
        seen.add(outcome.rule_id)
        rule = expected_rules.get(outcome.rule_id)
        if rule is None:
            raise ValidationError(f"hallazgo de una regla fuera del perfil: {outcome.rule_id}")
        if outcome.severity is not rule.severity or outcome.expected != rule.expected:
            raise ValidationError(f"el hallazgo {outcome.rule_id} no coincide con su regla")
        _check_status(outcome, rule)
    if seen != set(expected_rules):
        raise ValidationError("la evaluación no contiene todas las reglas de su perfil")


def _check_identity(run: AuditRun) -> None:
    try:
        parsed = uuid.UUID(run.run_id)
    except ValueError:
        raise ValidationError("el identificador de la evaluación no es un UUID") from None
    if parsed.version != 4 or str(parsed) != run.run_id:
        raise ValidationError("el identificador de la evaluación debe ser un UUID v4 en minúsculas")
    if COMPANY_ID.fullmatch(run.company_id) is None:
        raise ValidationError("el identificador de empresa no es válido")
    if not run.username.strip():
        raise ValidationError("la evaluación no tiene usuario")


def _check_status(outcome: Outcome, rule: Rule) -> None:
    if outcome.status is Status.NO_EVALUABLE:
        if outcome.observed is not None:
            raise ValidationError(f"{outcome.rule_id}: no evaluable no puede tener valor")
        return
    if not _is_scalar(outcome.observed):
        raise ValidationError(f"{outcome.rule_id}: el valor observado no es un escalar")
    if outcome.observed is None:
        if outcome.status is not Status.NO_CUMPLE:
            raise ValidationError(f"{outcome.rule_id}: un valor null no puede cumplir la regla")
        return
    cumple = meets(rule, outcome.observed)
    if cumple != (outcome.status is Status.CUMPLE):
        raise ValidationError(f"{outcome.rule_id}: el estado no corresponde al valor observado")


def _is_scalar(value: object) -> bool:
    return value is None or isinstance(value, str | int | bool)


def to_record(run: AuditRun) -> dict[str, object]:
    """Registro en español para la terminal y para los informes. Solo contiene escalares y listas."""
    return {
        "id": run.run_id,
        "empresa": run.company_id,
        "usuario": run.username,
        "perfil": run.profile,
        "sobrescrituras": {rule_id: value for rule_id, value in sorted(run.overrides.items())},
        "autorizacion": run.authorization_reference,
        "huella_configuracion": run.snapshot_sha256,
        "motor": run.engine_version,
        "inicio": to_iso(run.started_at),
        "fin": to_iso(run.finished_at),
        "resumen": {
            "cumple": run.passed,
            "no_cumple": run.failed,
            "no_evaluable": run.not_evaluable,
            "riesgo": run.risk,
        },
        "hallazgos": [
            {
                "regla": outcome.rule_id,
                "titulo": outcome.title,
                "ruta": outcome.path,
                "estado": outcome.status.value,
                "gravedad": outcome.severity.value,
                "valor_observado": outcome.observed,
                "valor_esperado": outcome.expected,
                "recomendacion": outcome.recommendation,
            }
            for outcome in run.outcomes
        ],
    }
