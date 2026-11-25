"""Servicio de auditoría con el núcleo real: permisos, ámbito de empresa, transacciones e inmutabilidad."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from natxajo_auditor.core.exceptions import AuthorizationError, StorageError, ValidationError
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import SERVICE_DATABASE, Kernel
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database
from tests.auditoria_datos import GOOD, WEAK, copy_of
from tests.conftest import install_administrator

PASSWORD = "contraseña-de-prueba-3"
AUTH = "Autorización escrita AUT-2026-001, firmada el 2026-11-01"


@pytest.fixture
def world(kernel: Kernel) -> Kernel:
    install_administrator(kernel)
    security = kernel.security
    security.companies.create("acme", "Acme S.A.")
    security.companies.create("globex", "Globex S.A.")
    security.create_account("admin_acme", PASSWORD, ["administrador"], "acme")
    security.create_account("operador_acme", PASSWORD, ["operador"], "acme")
    security.create_account("auditor_acme", PASSWORD, ["auditor"], "acme")
    security.create_account("admin_globex", PASSWORD, ["administrador"], "globex")
    return kernel


def _login(kernel: Kernel, username: str) -> str:
    return kernel.security.login(username, PASSWORD)


def _count(kernel: Kernel, table: str) -> int:
    database = cast(Database, kernel.services.get(SERVICE_DATABASE))
    return int(database.fetchall(f"SELECT COUNT(*) FROM {table}")[0][0])


def _events(kernel: Kernel, event_type: str) -> list[dict[str, object]]:
    return kernel.audit.events_of_type(event_type)


def test_the_platform_runs_an_evaluation_and_it_is_recorded(
    world: Kernel, platform_token: str
) -> None:
    record = world.auditing.run_document(
        platform_token, "acme", copy_of(GOOD), authorization_reference=AUTH
    )
    assert record["empresa"] == "acme"
    assert record["resumen"] == {
        "cumple": 17,
        "no_cumple": 0,
        "no_evaluable": 0,
        "riesgo": "ninguno",
    }
    assert _count(world, "audit_runs") == 1
    assert _count(world, "audit_findings") == 17
    recorded = _events(world, "audit.run_recorded")
    assert len(recorded) == 1
    assert str(record["id"]) in str(recorded[0])


def test_a_company_administrator_runs_only_for_its_own_company(
    world: Kernel, platform_token: str
) -> None:
    token = _login(world, "admin_acme")
    record = world.auditing.run_document(token, "acme", copy_of(WEAK), authorization_reference=AUTH)
    assert record["empresa"] == "acme"
    with pytest.raises(AuthorizationError):
        world.auditing.run_document(token, "globex", copy_of(WEAK), authorization_reference=AUTH)
    assert _count(world, "audit_runs") == 1
    denied = _events(world, "operation.denied")
    assert any("globex" in str(event) for event in denied)


def test_an_operator_without_the_permission_cannot_run_an_evaluation(world: Kernel) -> None:
    token = _login(world, "operador_acme")
    with pytest.raises(AuthorizationError):
        world.auditing.run_document(token, "acme", copy_of(GOOD), authorization_reference=AUTH)
    assert _count(world, "audit_runs") == 0


def test_an_auditor_reads_but_does_not_run(world: Kernel) -> None:
    token = _login(world, "auditor_acme")
    with pytest.raises(AuthorizationError):
        world.auditing.run_document(token, "acme", copy_of(GOOD), authorization_reference=AUTH)
    assert world.auditing.history(token, "acme") == []


def test_history_is_isolated_by_company(world: Kernel, platform_token: str) -> None:
    world.auditing.run_document(platform_token, "acme", copy_of(GOOD), authorization_reference=AUTH)
    world.auditing.run_document(
        platform_token, "globex", copy_of(WEAK), authorization_reference=AUTH
    )
    acme_admin = _login(world, "admin_acme")
    assert [item["empresa"] for item in world.auditing.history(acme_admin, "acme")] == ["acme"]
    with pytest.raises(AuthorizationError):
        world.auditing.history(acme_admin, "globex")
    with pytest.raises(AuthorizationError):
        world.auditing.history(acme_admin, None)
    assert len(world.auditing.history(platform_token, None)) == 2
    assert len(world.auditing.history(platform_token, "acme")) == 1


def test_another_companys_run_looks_exactly_like_a_missing_one(
    world: Kernel, platform_token: str
) -> None:
    other = world.auditing.run_document(
        platform_token, "globex", copy_of(GOOD), authorization_reference=AUTH
    )
    token = _login(world, "admin_acme")
    with pytest.raises(ValidationError) as foreign:
        world.auditing.get_run(token, "acme", str(other["id"]))
    with pytest.raises(ValidationError) as missing:
        world.auditing.get_run(token, "acme", str(uuid.uuid4()))
    assert str(foreign.value) == str(missing.value) == "evaluación no encontrada"


def test_a_stored_run_loads_back_identical(world: Kernel, platform_token: str) -> None:
    record = world.auditing.run_document(
        platform_token, "acme", copy_of(WEAK), authorization_reference=AUTH
    )
    loaded = world.auditing.get_run(platform_token, "acme", str(record["id"]))
    assert loaded == record


def test_an_invalid_session_is_rejected_before_anything_happens(world: Kernel) -> None:
    with pytest.raises(AuthorizationError):
        world.auditing.run_document(
            "ficha-falsa", "acme", copy_of(GOOD), authorization_reference=AUTH
        )
    assert _count(world, "audit_runs") == 0
    with pytest.raises(AuthorizationError):
        world.auditing.rules("ficha-falsa")


@pytest.mark.parametrize("reference", ["", "  ab  ", "x" * 201, "ref\x07con-control"])
def test_the_written_authorization_reference_is_mandatory(
    world: Kernel, platform_token: str, reference: str
) -> None:
    with pytest.raises(ValidationError, match="referencia escrita"):
        world.auditing.run_document(
            platform_token, "acme", copy_of(GOOD), authorization_reference=reference
        )
    assert _count(world, "audit_runs") == 0


def test_an_interrupted_evaluation_leaves_no_rows_behind(
    world: Kernel, platform_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = AuditLog.record

    def failing(
        self: AuditLog,
        event_type: str,
        payload: object,
        connection: object = None,
        **kwargs: object,
    ) -> None:
        if event_type == "audit.run_recorded":
            raise RuntimeError("fallo simulado al registrar la evaluación")
        original(self, event_type, payload, connection, **kwargs)

    monkeypatch.setattr(AuditLog, "record", failing)
    with pytest.raises(RuntimeError):
        world.auditing.run_document(
            platform_token, "acme", copy_of(GOOD), authorization_reference=AUTH
        )
    assert _count(world, "audit_runs") == 0
    assert _count(world, "audit_findings") == 0


def test_stored_evaluations_are_immutable(world: Kernel, platform_token: str) -> None:
    record = world.auditing.run_document(
        platform_token, "acme", copy_of(WEAK), authorization_reference=AUTH
    )
    database = cast(Database, world.services.get(SERVICE_DATABASE))
    with pytest.raises(StorageError):
        database.execute("UPDATE audit_runs SET passed = 99 WHERE id = ?", (record["id"],))
    with pytest.raises(StorageError):
        database.execute("DELETE FROM audit_findings WHERE run_id = ?", (record["id"],))


def test_a_tampered_finding_is_detected_when_the_run_is_loaded(
    world: Kernel, platform_token: str
) -> None:
    record = world.auditing.run_document(
        platform_token, "acme", copy_of(WEAK), authorization_reference=AUTH
    )
    database = cast(Database, world.services.get(SERVICE_DATABASE))
    # Un atacante con acceso al archivo podría quitar el disparador. El núcleo debe detectarlo.
    database.execute("DROP TRIGGER audit_findings_are_immutable")
    database.execute(
        "UPDATE audit_findings SET status = 'cumple' WHERE run_id = ? AND rule_id = 'AUT-001'",
        (record["id"],),
    )
    with pytest.raises(StorageError, match="inconsistente"):
        world.auditing.get_run(platform_token, "acme", str(record["id"]))


def test_overrides_are_applied_and_recorded_in_the_run(world: Kernel, platform_token: str) -> None:
    record = world.auditing.run_document(
        platform_token,
        "acme",
        copy_of(GOOD),
        authorization_reference=AUTH,
        overrides={"AUT-001": 14},
    )
    assert record["sobrescrituras"] == {"AUT-001": 14}
    findings = record["hallazgos"]
    assert isinstance(findings, list)
    first = next(item for item in findings if item["regla"] == "AUT-001")
    assert first["valor_esperado"] == "al menos 14"
    with pytest.raises(ValidationError):
        world.auditing.run_document(
            platform_token,
            "acme",
            copy_of(GOOD),
            authorization_reference=AUTH,
            overrides={"AUT-001": 3},
        )
    with pytest.raises(ValidationError):
        world.auditing.run_document(
            platform_token,
            "acme",
            copy_of(GOOD),
            authorization_reference=AUTH,
            overrides={"AUT-004": 3},
        )


def test_a_file_is_read_only_after_the_permission_check(world: Kernel) -> None:
    token = _login(world, "operador_acme")
    missing = Path("ruta-que-no-existe") / "config.json"
    with pytest.raises(AuthorizationError):
        world.auditing.run_file(token, "acme", missing, authorization_reference=AUTH)


@pytest.fixture
def spaced_folder(tmp_path: Path) -> Iterator[Path]:
    folder = tmp_path / "Carpeta con espacios ñ (prueba) #1"
    folder.mkdir()
    yield folder


def test_a_file_in_a_folder_with_spaces_is_evaluated(
    world: Kernel, platform_token: str, spaced_folder: Path
) -> None:
    target = spaced_folder / "configuración acme.json"
    target.write_text(json.dumps(GOOD, ensure_ascii=False), encoding="utf-8")
    record = world.auditing.run_file(platform_token, "acme", target, authorization_reference=AUTH)
    assert record["resumen"] == {
        "cumple": 17,
        "no_cumple": 0,
        "no_evaluable": 0,
        "riesgo": "ninguno",
    }


def test_the_rules_catalog_needs_a_session_and_lists_every_rule(
    world: Kernel, platform_token: str
) -> None:
    rules = world.auditing.rules(platform_token)
    assert len(rules) == 17
    assert rules[0]["gravedad"] == "critico"


def test_run_identifiers_are_validated_before_any_lookup(
    world: Kernel, platform_token: str
) -> None:
    with pytest.raises(ValidationError):
        world.auditing.get_run(platform_token, "acme", "../../etc/passwd")
    with pytest.raises(ValidationError):
        world.auditing.get_run(platform_token, "Acme Corp", str(uuid.uuid4()))


def test_a_separate_kernel_with_a_spaced_project_root_starts(tmp_path: Path) -> None:
    context = RuntimeContext(project_root=tmp_path / "Proyecto con espacios ñandú")
    kernel = Kernel(context, password_iterations=1_000)
    kernel.start()
    try:
        assert kernel.auditing is not None and kernel.reports is not None
    finally:
        kernel.stop()
