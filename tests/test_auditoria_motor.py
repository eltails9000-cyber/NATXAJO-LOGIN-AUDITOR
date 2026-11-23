"""Motor de auditoría sin base de datos: catálogo, esquema, evaluación, invariantes y lectura de archivos.

Cada prueba de rechazo comprueba también que el mensaje de error no repite el valor recibido.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from natxajo_auditor.auditing.catalog import (
    BUILTIN_RULES,
    RULES_BY_ID,
    Operator,
    Rule,
    Severity,
    Status,
    apply_override,
)
from natxajo_auditor.auditing.engine import Outcome, evaluate, resolve_rules
from natxajo_auditor.auditing.loader import read_document
from natxajo_auditor.auditing.results import AuditRun, to_record, validate_run
from natxajo_auditor.auditing.snapshot import decode_document, parse_snapshot
from natxajo_auditor.core.exceptions import ValidationError
from tests.auditoria_datos import GOOD, WEAK, copy_of, without

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


def _run(document: dict[str, Any], profile: str = "completo") -> AuditRun:
    snapshot = parse_snapshot(document)
    rules = resolve_rules(profile, {})
    outcomes = evaluate(snapshot, rules)
    return AuditRun(
        run_id=str(uuid.uuid4()),
        company_id="acme",
        username="auditor_prueba",
        profile=profile,
        overrides={},
        authorization_reference="Autorización escrita AUT-2026-001",
        snapshot_sha256=snapshot.canonical_sha256(),
        engine_version="0.1.0",
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
        outcomes=outcomes,
    )


def _outcome(run: AuditRun, rule_id: str) -> Outcome:
    return next(item for item in run.outcomes if item.rule_id == rule_id)


# --- Catálogo -----------------------------------------------------------------------------------


def test_catalog_has_unique_ids_and_spanish_texts() -> None:
    assert len(RULES_BY_ID) == len(BUILTIN_RULES) == 17
    for rule in BUILTIN_RULES:
        assert rule.title.strip() and rule.recommendation.strip(), rule.id
        assert rule.id.startswith("AUT-")


def test_rule_shapes_are_checked_at_construction() -> None:
    with pytest.raises(ValidationError):
        Rule("X-1", "t", "s", "f", Operator.AT_LEAST, Severity.BAJO, "r")  # falta minimum
    with pytest.raises(ValidationError):
        Rule("X-2", "t", "s", "f", Operator.RANGE, Severity.BAJO, "r", minimum=5, maximum=1)
    with pytest.raises(ValidationError):
        Rule("X-3", "t", "s", "f", Operator.ONE_OF, Severity.BAJO, "r")  # sin valores aceptados
    with pytest.raises(ValidationError):
        Rule("X-4", "t", "s", "f", Operator.IS_TRUE, Severity.BAJO, "r", minimum=1)
    with pytest.raises(ValidationError):
        Rule(
            "X-5",
            "t",
            "s",
            "f",
            Operator.RANGE,
            Severity.BAJO,
            "r",
            minimum=1,
            maximum=2,
            overridable=(1, 2),
        )


def test_override_respects_the_fixed_limits() -> None:
    rule = RULES_BY_ID["AUT-001"]
    assert apply_override(rule, 14).minimum == 14
    assert apply_override(rule, 8).minimum == 8
    with pytest.raises(ValidationError):
        apply_override(rule, 7)  # por debajo del límite inferior
    with pytest.raises(ValidationError):
        apply_override(rule, 129)
    with pytest.raises(ValidationError):
        apply_override(rule, True)  # un booleano no es un umbral
    with pytest.raises(ValidationError):
        apply_override(RULES_BY_ID["AUT-004"], 3)  # las reglas de rango no admiten sobrescritura


def test_profiles_select_rules_and_reject_unknown_names() -> None:
    assert len(resolve_rules("completo", {})) == 17
    critical = resolve_rules("critico", {})
    assert {rule.severity for rule in critical} <= {Severity.ALTO, Severity.CRITICO}
    with pytest.raises(ValidationError):
        resolve_rules("inexistente", {})
    with pytest.raises(ValidationError):
        resolve_rules("completo", {"AUT-999": 1})
    with pytest.raises(ValidationError):
        resolve_rules("critico", {"AUT-002": 1})  # AUT-002 es media: no está en el perfil crítico


def test_overrides_change_the_expected_text_of_the_rule() -> None:
    rules = {rule.id: rule for rule in resolve_rules("completo", {"AUT-001": 14})}
    assert rules["AUT-001"].expected == "al menos 14"
    assert RULES_BY_ID["AUT-001"].expected == "al menos 12"


# --- Esquema del documento ----------------------------------------------------------------------


def test_a_complete_document_is_accepted_and_hashed_canonically() -> None:
    snapshot = parse_snapshot(copy_of(GOOD))
    reordered = dict(reversed(list(copy_of(GOOD).items())))
    spaced = decode_document(json.dumps(reordered, indent=7))
    assert parse_snapshot(spaced).canonical_sha256() == snapshot.canonical_sha256()
    changed = copy_of(GOOD)
    changed["contrasenas"]["longitud_minima"] = 13
    assert parse_snapshot(changed).canonical_sha256() != snapshot.canonical_sha256()


@pytest.mark.parametrize(
    ("mutate", "fragment"),
    [
        (lambda d: d.update({"clave_desconocida_raiz": 1}), "nivel raíz"),
        (lambda d: d["contrasenas"].update({"contrasena_real": "x"}), "contrasenas"),
        (lambda d: d.update({"esquema": 2}), "esquema"),
        (lambda d: d.update({"esquema": True}), "esquema"),
        (lambda d: d.update({"contrasenas": "texto"}), "debe ser un objeto"),
        (
            lambda d: d["contrasenas"].update({"longitud_minima": "12"}),
            "contrasenas.longitud_minima",
        ),
        (
            lambda d: d["contrasenas"].update({"longitud_minima": True}),
            "contrasenas.longitud_minima",
        ),
        (lambda d: d["contrasenas"].update({"longitud_minima": 0}), "contrasenas.longitud_minima"),
        (lambda d: d["contrasenas"].update({"complejidad": 1}), "contrasenas.complejidad"),
        (lambda d: d["contrasenas"].update({"algoritmo": "rot13"}), "contrasenas.algoritmo"),
        (lambda d: d["cookies"].update({"same_site": "Any"}), "cookies.same_site"),
    ],
)
def test_invalid_documents_are_rejected(mutate: Any, fragment: str) -> None:
    document = copy_of(GOOD)
    mutate(document)
    with pytest.raises(ValidationError) as error:
        parse_snapshot(document)
    assert fragment in str(error.value)


def test_rejection_messages_never_repeat_the_received_secret() -> None:
    secret = "S3cr3t-valor-que-no-debe-salir-9f2"
    document = copy_of(GOOD)
    document["contrasenas"][secret] = secret  # clave y valor con forma de credencial
    with pytest.raises(ValidationError) as error:
        parse_snapshot(document)
    assert secret not in str(error.value)

    document = copy_of(GOOD)
    document["contrasenas"]["algoritmo"] = secret
    with pytest.raises(ValidationError) as error:
        parse_snapshot(document)
    assert secret not in str(error.value)


def test_strict_json_rejects_duplicates_constants_and_garbage() -> None:
    with pytest.raises(ValidationError, match="repite una clave"):
        decode_document('{"esquema": 1, "esquema": 1}')
    with pytest.raises(ValidationError, match="número no admitido"):
        decode_document('{"esquema": NaN}')
    with pytest.raises(ValidationError, match="JSON no válido"):
        decode_document("{esquema: 1")
    with pytest.raises(ValidationError, match="anidado en exceso"):
        decode_document("[" * 100_000 + "]" * 100_000)


# --- Evaluación ---------------------------------------------------------------------------------


def test_a_compliant_document_passes_every_rule() -> None:
    run = _run(copy_of(GOOD))
    assert (run.passed, run.failed, run.not_evaluable, run.risk) == (17, 0, 0, "ninguno")


def test_a_weak_document_fails_every_rule_and_reports_the_highest_severity() -> None:
    run = _run(copy_of(WEAK))
    assert (run.passed, run.failed, run.not_evaluable) == (0, 17, 0)
    assert run.risk == "critico"
    assert _outcome(run, "AUT-009").observed is None  # null: declarado sin configurar
    assert _outcome(run, "AUT-003").observed == "md5"


def test_missing_sections_are_not_evaluable_not_failing() -> None:
    run = _run(without(GOOD, "mfa", "frecuencia"))
    assert _outcome(run, "AUT-015").status is Status.NO_EVALUABLE
    assert _outcome(run, "AUT-015").observed is None
    assert (run.passed, run.failed, run.not_evaluable) == (14, 0, 3)
    assert run.risk == "ninguno"


@pytest.mark.parametrize(
    ("value", "passes"),
    [(0, False), (1, True), (10, True), (11, False)],
)
def test_range_rule_edges(value: int, passes: bool) -> None:
    document = copy_of(GOOD)
    document["bloqueo"]["intentos_maximos"] = value
    assert _outcome(_run(document), "AUT-004").status is (
        Status.CUMPLE if passes else Status.NO_CUMPLE
    )


def test_threshold_rules_respect_their_limits_inclusively() -> None:
    document = copy_of(GOOD)
    document["contrasenas"]["longitud_minima"] = 11
    assert _outcome(_run(document), "AUT-001").status is Status.NO_CUMPLE
    document["contrasenas"]["longitud_minima"] = 12
    assert _outcome(_run(document), "AUT-001").status is Status.CUMPLE


def test_a_stricter_override_turns_a_compliant_value_into_a_failure() -> None:
    rules = resolve_rules("completo", {"AUT-001": 16})
    outcomes = evaluate(parse_snapshot(copy_of(GOOD)), rules)
    failing = next(item for item in outcomes if item.rule_id == "AUT-001")
    assert failing.status is Status.NO_CUMPLE
    assert failing.expected == "al menos 16"


# --- Resultados e invariantes -------------------------------------------------------------------


def test_a_fresh_run_passes_validation_and_serializes_in_spanish() -> None:
    run = _run(copy_of(WEAK))
    validate_run(run)
    record = to_record(run)
    assert record["resumen"] == {
        "cumple": 0,
        "no_cumple": 17,
        "no_evaluable": 0,
        "riesgo": "critico",
    }
    findings = record["hallazgos"]
    assert isinstance(findings, list) and len(findings) == 17
    assert set(findings[0]) == {
        "regla",
        "titulo",
        "ruta",
        "estado",
        "gravedad",
        "valor_observado",
        "valor_esperado",
        "recomendacion",
    }


def test_validation_detects_a_status_that_contradicts_the_value() -> None:
    run = _run(copy_of(WEAK))
    tampered = tuple(
        dataclasses.replace(item, status=Status.CUMPLE) if item.rule_id == "AUT-001" else item
        for item in run.outcomes
    )
    with pytest.raises(ValidationError, match="no corresponde"):
        validate_run(dataclasses.replace(run, outcomes=tampered))


def test_validation_detects_missing_extra_and_repeated_findings() -> None:
    run = _run(copy_of(GOOD))
    with pytest.raises(ValidationError, match="todas las reglas"):
        validate_run(dataclasses.replace(run, outcomes=run.outcomes[:-1]))
    with pytest.raises(ValidationError, match="repetido"):
        validate_run(dataclasses.replace(run, outcomes=(*run.outcomes, run.outcomes[0])))
    alien = dataclasses.replace(run.outcomes[0], rule_id="AUT-999")
    with pytest.raises(ValidationError, match="fuera del perfil"):
        validate_run(dataclasses.replace(run, outcomes=(alien, *run.outcomes[1:])))


def test_validation_detects_a_wrong_severity_or_expected_text() -> None:
    run = _run(copy_of(GOOD))
    first = run.outcomes[0]
    wrong = dataclasses.replace(
        first, severity=Severity.BAJO if first.severity is not Severity.BAJO else Severity.ALTO
    )
    with pytest.raises(ValidationError, match="no coincide"):
        validate_run(dataclasses.replace(run, outcomes=(wrong, *run.outcomes[1:])))
    stale = dataclasses.replace(first, expected="al menos 1")
    with pytest.raises(ValidationError, match="no coincide"):
        validate_run(dataclasses.replace(run, outcomes=(stale, *run.outcomes[1:])))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"run_id": "no-es-uuid"}, "UUID"),
        ({"run_id": str(uuid.uuid1())}, "UUID v4"),
        ({"run_id": str(uuid.uuid4()).upper()}, "minúsculas"),
        ({"company_id": "Acme Corp"}, "empresa"),
        ({"authorization_reference": "ab"}, "referencia"),
        ({"authorization_reference": "x" * 201}, "referencia"),
        ({"authorization_reference": "ref\u0007con-control"}, "no imprimibles"),
        ({"snapshot_sha256": "abc"}, "SHA-256"),
        ({"profile": "inexistente"}, "perfil"),
        ({"finished_at": NOW - timedelta(seconds=1)}, "antes de empezar"),
        ({"engine_version": " "}, "versión del motor"),
        ({"username": ""}, "usuario"),
    ],
)
def test_validation_rejects_bad_run_metadata(changes: dict[str, object], message: str) -> None:
    run = dataclasses.replace(_run(copy_of(GOOD)), **changes)
    with pytest.raises(ValidationError, match=message):
        validate_run(run)


def test_risk_is_none_only_when_no_rule_fails() -> None:
    run = _run(without(GOOD, "mfa"))
    assert run.risk == "ninguno"
    assert _run(copy_of(WEAK)).risk == "critico"


# --- Lectura de archivos ------------------------------------------------------------------------


def test_documents_in_folders_with_spaces_and_special_characters_are_read(tmp_path: Path) -> None:
    folder = tmp_path / "Auditorías ñandú (2026) #1"
    folder.mkdir()
    target = folder / "configuración de acme.json"
    target.write_text(json.dumps(GOOD, ensure_ascii=False), encoding="utf-8")
    assert read_document(target) == GOOD


def test_a_utf8_bom_written_by_an_editor_is_accepted(tmp_path: Path) -> None:
    target = tmp_path / "bom.json"
    target.write_bytes(b"\xef\xbb\xbf" + json.dumps(GOOD).encode("utf-8"))
    assert read_document(target) == GOOD


def test_file_reading_limits_and_errors(tmp_path: Path) -> None:
    big = tmp_path / "grande.json"
    big.write_text(json.dumps(GOOD), encoding="utf-8")
    with pytest.raises(ValidationError, match="tamaño máximo"):
        read_document(big, max_bytes=10)
    with pytest.raises(ValidationError, match="no existe"):
        read_document(tmp_path / "no-existe.json")
    with pytest.raises(ValidationError, match="regular"):
        read_document(tmp_path)  # una carpeta no es un documento
    latin = tmp_path / "latin.json"
    latin.write_bytes('{"x": "ñ"}'.encode("latin-1"))
    with pytest.raises(ValidationError, match="UTF-8"):
        read_document(latin)


def test_a_symbolic_link_is_not_followed(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text(json.dumps(GOOD), encoding="utf-8")
    link = tmp_path / "enlace.json"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("este sistema no permite crear enlaces simbólicos")
    with pytest.raises(ValidationError, match="enlace simbólico"):
        read_document(link)


def test_rules_catalog_is_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        RULES_BY_ID["AUT-001"].minimum = 1  # type: ignore[misc]
    assert isinstance(BUILTIN_RULES[0], Rule)
    assert isinstance(
        Outcome("AUT-001", "t", "p", Status.CUMPLE, Severity.BAJO, 1, "e", "r"), Outcome
    )
