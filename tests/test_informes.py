"""Informes: contenido de cada formato, escape, exportación con permisos, registro y verificación."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from natxajo_auditor.auditing.catalog import Severity, Status
from natxajo_auditor.auditing.engine import Outcome
from natxajo_auditor.auditing.results import AuditRun
from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import SERVICE_DATABASE, Kernel
from natxajo_auditor.reporting.formats import FORMATS, ReportMeta, render
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database
from tests.auditoria_datos import GOOD, WEAK, copy_of
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator

PASSWORD = "contraseña-de-prueba-4"
AUTH = "Autorización escrita AUT-2026-002"
NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
META = ReportMeta(
    report_id=str(uuid.uuid4()),
    generated_at="2026-11-22T12:00:00+00:00",
    platform_version="0.1.0",
    username="auditor_prueba",
)


def _crafted(observed: str, title: str = "Algoritmo de contraseñas") -> AuditRun:
    """Evaluación construida a mano para probar el renderizado con valores hostiles."""
    outcome = Outcome(
        rule_id="AUT-003",
        title=title,
        path="contrasenas.algoritmo",
        status=Status.NO_CUMPLE,
        severity=Severity.CRITICO,
        observed=observed,
        expected="uno de: argon2id, bcrypt, pbkdf2-sha256, scrypt",
        recommendation="Use argon2id.",
    )
    return AuditRun(
        run_id=str(uuid.uuid4()),
        company_id="acme",
        username="auditor_prueba",
        profile="completo",
        overrides={},
        authorization_reference=AUTH,
        snapshot_sha256="a" * 64,
        engine_version="0.1.0",
        started_at=NOW,
        finished_at=NOW,
        outcomes=(outcome,),
    )


# --- Contenido de los formatos ------------------------------------------------------------------


def test_json_is_valid_and_carries_the_methodology_and_the_evaluation() -> None:
    run = _crafted("md5")
    document = json.loads(render(run, META, "json"))
    assert document["informe"]["metodologia"].startswith("Evaluación sin conexión")
    assert document["informe"]["version_plataforma"] == "0.1.0"
    assert document["evaluacion"]["id"] == run.run_id
    assert document["evaluacion"]["resumen"]["riesgo"] == "critico"


def test_csv_has_a_header_and_one_row_per_finding_and_neutralizes_formulas() -> None:
    run = _crafted('=HYPERLINK("http://ejemplo.invalid","x")')
    text = render(run, META, "csv").decode("utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == [
        "regla",
        "titulo",
        "ruta",
        "estado",
        "gravedad",
        "valor_observado",
        "valor_esperado",
        "recomendacion",
    ]
    assert len(rows) == 2
    assert rows[1][5].startswith("'=HYPERLINK")


@pytest.mark.parametrize("hostile", ["+1+1", "-2+3", "@SUM(A1)", "\tcmd"])
def test_every_formula_prefix_is_neutralized(hostile: str) -> None:
    rows = list(csv.reader(io.StringIO(render(_crafted(hostile), META, "csv").decode("utf-8"))))
    assert rows[1][5].startswith("'")


def test_html_escapes_every_value_and_loads_nothing_external() -> None:
    run = _crafted("<script>alert('x')</script>", title="<img src=x onerror=alert(1)>")
    page = render(run, META, "html").decode("utf-8")
    assert "<script>alert" not in page
    assert "&lt;script&gt;" in page
    assert "<img src=x" not in page
    assert "&lt;img src=x" in page
    assert "http://" not in page and "https://" not in page
    assert '<html lang="es">' in page


def test_txt_states_the_summary_and_the_methodology() -> None:
    text = render(_crafted("md5"), META, "txt").decode("utf-8")
    assert "INFORME DE AUDITORÍA DE CONFIGURACIÓN" in text
    assert "riesgo más alto critico" in text
    assert "Ninguna solicitud se envía al sistema evaluado" in text


def test_every_declared_format_renders() -> None:
    assert FORMATS == ("json", "csv", "html", "txt")
    for fmt in FORMATS:
        assert render(_crafted("md5"), META, fmt)
    with pytest.raises(ValueError):
        render(_crafted("md5"), META, "pdf")


# --- Exportación con el núcleo real -------------------------------------------------------------


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


def _evaluate(kernel: Kernel, token: str, company: str, document: dict[str, object]) -> str:
    record = kernel.auditing.run_document(token, company, document, authorization_reference=AUTH)
    return str(record["id"])


def test_an_export_writes_a_file_registers_its_digest_and_verifies_clean(
    world: Kernel, platform_token: str
) -> None:
    run_id = _evaluate(world, platform_token, "acme", copy_of(WEAK))
    exported = world.reports.export(platform_token, "acme", run_id, "json")
    path = world.context.reports_dir / str(exported["ruta"])
    content = path.read_bytes()
    assert hashlib.sha256(content).hexdigest() == exported["sha256"]
    assert exported["bytes"] == len(content)
    assert re.fullmatch(rf"acme/informe-{run_id}-[0-9a-f-]{{36}}\.json", str(exported["ruta"]))
    assert _count(world, "report_exports") == 1
    history = world.reports.history(platform_token, "acme")
    assert [item["evaluacion"] for item in history] == [run_id]
    assert world.reports.verify(platform_token, "acme") == [
        {"id": exported["id"], "ruta": exported["ruta"], "estado": "correcto"}
    ]
    events = world.audit.events_of_type("report.exported")
    assert len(events) == 1


def test_exporting_needs_the_export_permission_and_reading_needs_the_read_permission(
    world: Kernel, platform_token: str
) -> None:
    run_id = _evaluate(world, platform_token, "acme", copy_of(GOOD))
    auditor = _login(world, "auditor_acme")
    with pytest.raises(AuthorizationError):
        world.reports.export(auditor, "acme", run_id, "csv")
    operator = _login(world, "operador_acme")
    with pytest.raises(AuthorizationError):
        world.reports.export(operator, "acme", run_id, "csv")
    assert world.reports.history(auditor, "acme") == []
    assert _count(world, "report_exports") == 0


def test_exports_are_isolated_by_company(world: Kernel, platform_token: str) -> None:
    run_id = _evaluate(world, platform_token, "acme", copy_of(GOOD))
    foreign_admin = _login(world, "admin_globex")
    with pytest.raises(ValidationError, match="evaluación no encontrada"):
        world.reports.export(foreign_admin, "globex", run_id, "json")
    acme_admin = _login(world, "admin_acme")
    with pytest.raises(AuthorizationError):
        world.reports.history(acme_admin, "globex")
    with pytest.raises(AuthorizationError):
        world.reports.history(acme_admin, None)


def test_unsupported_formats_and_bad_company_identifiers_are_rejected(
    world: Kernel, platform_token: str
) -> None:
    run_id = _evaluate(world, platform_token, "acme", copy_of(GOOD))
    with pytest.raises(ValidationError, match="formato no soportado"):
        world.reports.export(platform_token, "acme", run_id, "pdf")
    with pytest.raises(ValidationError, match="empresa"):
        world.reports.export(platform_token, "../acme", run_id, "json")
    assert _count(world, "report_exports") == 0


def test_a_failed_export_leaves_no_file_and_no_row_and_is_recorded(
    world: Kernel, platform_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_id = _evaluate(world, platform_token, "acme", copy_of(WEAK))
    original = AuditLog.record

    def failing(
        self: AuditLog,
        event_type: str,
        payload: object,
        connection: object = None,
        **kwargs: object,
    ) -> None:
        if event_type == "report.exported":
            raise RuntimeError("fallo simulado al registrar el informe")
        original(self, event_type, payload, connection, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(AuditLog, "record", failing)
    with pytest.raises(RuntimeError):
        world.reports.export(platform_token, "acme", run_id, "html")
    monkeypatch.undo()
    folder = world.context.reports_dir / "acme"
    assert not folder.exists() or list(folder.iterdir()) == []
    assert _count(world, "report_exports") == 0
    failures = world.audit.events_of_type("report.failed")
    assert len(failures) == 1


def test_verification_detects_altered_missing_and_orphan_files(
    world: Kernel, platform_token: str
) -> None:
    run_id = _evaluate(world, platform_token, "acme", copy_of(WEAK))
    first = world.reports.export(platform_token, "acme", run_id, "json")
    second = world.reports.export(platform_token, "acme", run_id, "csv")
    third = world.reports.export(platform_token, "acme", run_id, "txt")
    root = world.context.reports_dir
    with (root / str(first["ruta"])).open("ab") as handle:
        handle.write(b"x")
    (root / str(second["ruta"])).unlink()
    orphan = root / "acme" / f"informe-{run_id}-{uuid.uuid4()}.html"
    orphan.write_text("<p>sin registro</p>", encoding="utf-8")

    states = {
        str(item["ruta"]): item["estado"] for item in world.reports.verify(platform_token, "acme")
    }
    assert states[str(first["ruta"])] == "alterado"
    assert states[str(second["ruta"])] == "faltante"
    assert states[str(third["ruta"])] == "correcto"
    assert states[f"acme/{orphan.name}"] == "huerfano"


def test_reports_are_written_under_a_folder_with_spaces_and_unicode(tmp_path: Path) -> None:
    context = RuntimeContext(project_root=tmp_path / "Proyecto de prueba ñandú (2026)")
    kernel = Kernel(context, password_iterations=1_000)
    kernel.start()
    try:
        install_administrator(kernel)
        kernel.security.companies.create("acme", "Acme S.A.")
        platform = kernel.security.login(ADMIN_USER, ADMIN_PASSWORD)
        run_id = _evaluate(kernel, platform, "acme", copy_of(GOOD))
        exported = kernel.reports.export(platform, "acme", run_id, "txt")
        assert (context.reports_dir / str(exported["ruta"])).is_file()
    finally:
        kernel.stop()
