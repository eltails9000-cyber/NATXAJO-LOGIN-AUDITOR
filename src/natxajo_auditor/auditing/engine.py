"""Motor de evaluación: resuelve el perfil con sus sobrescrituras y compara el documento con las reglas.

Es una función pura: no toca la base de datos, el disco ni la red. La persistencia, el permiso y
la auditoría son responsabilidad de `service.py`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from natxajo_auditor.auditing.catalog import (
    BUILTIN_RULES,
    PROFILE_MIN_SEVERITY,
    RULES_BY_ID,
    SEVERITY_RANK,
    Operator,
    Rule,
    Severity,
    Status,
    apply_override,
)
from natxajo_auditor.auditing.snapshot import Scalar, Snapshot
from natxajo_auditor.core.exceptions import ValidationError


@dataclass(frozen=True)
class Outcome:
    """Resultado de una regla en una evaluación. Contiene el texto de la regla usada, no solo su id."""

    rule_id: str
    title: str
    path: str
    status: Status
    severity: Severity
    observed: Scalar
    expected: str
    recommendation: str


def resolve_rules(profile: str, overrides: Mapping[str, object]) -> tuple[Rule, ...]:
    """Reglas del perfil con sus umbrales sobrescritos. Rechaza lo que no existe o no encaja."""
    if profile not in PROFILE_MIN_SEVERITY:
        options = ", ".join(sorted(PROFILE_MIN_SEVERITY))
        raise ValidationError(f"perfil desconocido: use uno de [{options}]")
    minimum = SEVERITY_RANK[PROFILE_MIN_SEVERITY[profile]]
    for rule_id in overrides:
        if rule_id not in RULES_BY_ID:
            raise ValidationError(f"sobrescritura de una regla desconocida: {rule_id!r}")
    selected: list[Rule] = []
    for rule in BUILTIN_RULES:
        if SEVERITY_RANK[rule.severity] < minimum:
            if rule.id in overrides:
                raise ValidationError(f"{rule.id} no pertenece al perfil {profile!r}")
            continue
        if rule.id in overrides:
            rule = apply_override(rule, overrides[rule.id])
        selected.append(rule)
    return tuple(selected)


def evaluate(snapshot: Snapshot, rules: Iterable[Rule]) -> tuple[Outcome, ...]:
    return tuple(_evaluate_one(snapshot, rule) for rule in rules)


def _evaluate_one(snapshot: Snapshot, rule: Rule) -> Outcome:
    if not snapshot.has(rule.section, rule.field):
        status = Status.NO_EVALUABLE
        observed: Scalar = None
    else:
        observed = snapshot.value(rule.section, rule.field)
        status = Status.CUMPLE if meets(rule, observed) else Status.NO_CUMPLE
    return Outcome(
        rule_id=rule.id,
        title=rule.title,
        path=rule.path,
        status=status,
        severity=rule.severity,
        observed=observed,
        expected=rule.expected,
        recommendation=rule.recommendation,
    )


def meets(rule: Rule, value: Scalar) -> bool:
    """True si el valor cumple la regla. Un valor null es un campo declarado sin configurar."""
    if value is None:
        return False
    if rule.operator is Operator.IS_TRUE:
        return value is True
    if rule.operator is Operator.ONE_OF:
        return isinstance(value, str) and value in rule.allowed
    if not isinstance(value, int) or isinstance(value, bool):
        return False
    if rule.operator is Operator.AT_LEAST:
        return rule.minimum is not None and value >= rule.minimum
    if rule.operator is Operator.AT_MOST:
        return rule.maximum is not None and value <= rule.maximum
    return (
        rule.minimum is not None
        and rule.maximum is not None
        and (rule.minimum <= value <= rule.maximum)
    )
