"""Terminal de la etapa 4: evaluaciones, informes y mantenimiento con permisos y confirmaciones.

Las respuestas se simulan con listas. Las cuentas son ficticias y los datos viven en carpetas
temporales.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Iterable
from pathlib import Path

import pytest

from natxajo_auditor.interfaces.terminal.app import run_terminal
from natxajo_auditor.kernel.kernel import Kernel
from tests.auditoria_datos import GOOD, copy_of
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER

REFERENCE = "Autorización escrita AUT-2026-010"
COMPANY_PASSWORD = "contraseña-de-prueba-7"


def _scripted(answers: Iterable[str]) -> Callable[[str], str]:
    iterator = iter(answers)

    def read(prompt: str) -> str:
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None

    return read


def _run(kernel: Kernel, reads: list[str], secrets: list[str], lines: list[str]) -> None:
    run_terminal(
        kernel,
        read=_scripted(reads),
        write=lines.append,
        read_secret=_scripted(secrets),
    )


@pytest.fixture
def acme(kernel: Kernel, admin: tuple[str, str]) -> Kernel:
    """Plataforma con dos empresas, un administrador y un auditor de la empresa acme."""
    kernel.security.companies.create("acme", "Acme S.A.")
    kernel.security.companies.create("globex", "Globex S.A.")
    kernel.security.create_account("admin_acme", COMPANY_PASSWORD, ["administrador"], "acme")
    kernel.security.create_account("auditor_acme", COMPANY_PASSWORD, ["auditor"], "acme")
    return kernel


def test_platform_evaluates_a_file_with_spaces_and_special_characters(
    acme: Kernel, tmp_path: Path
) -> None:
    folder = tmp_path / "Carpeta con espacios ñ (prueba)"
    folder.mkdir()
    target = folder / "configuración acme.json"
    target.write_text(json.dumps(GOOD, ensure_ascii=False), encoding="utf-8")
    lines: list[str] = []
    # Ruta entre comillas, como la copia «Copiar como ruta» de Windows.
    reads = [ADMIN_USER, "20", "acme", f'"{target}"', "", REFERENCE, ""]
    _run(acme, reads, [ADMIN_PASSWORD], lines)
    assert any(line.startswith("Cumple: 17 | No cumple: 0") for line in lines)
    assert len(acme.audit.events_of_type("audit.run_recorded")) == 1


def test_a_guarded_option_is_recorded_once_and_asks_no_extra_confirmation(
    acme: Kernel, tmp_path: Path
) -> None:
    target = tmp_path / "config.json"
    target.write_text(json.dumps(GOOD), encoding="utf-8")
    lines: list[str] = []
    _run(acme, [ADMIN_USER, "20", "acme", str(target), "", REFERENCE, ""], [ADMIN_PASSWORD], lines)
    assert len(acme.audit.events_of_type("audit.run_recorded")) == 1
    assert len(acme.audit.events_of_type("operation.executed")) == 1
    assert not any("¿Confirma la operación?" in line for line in lines)


def test_a_company_administrator_sees_and_runs_only_its_own_company(
    acme: Kernel, tmp_path: Path, platform_token: str
) -> None:
    foreign = acme.auditing.run_document(
        platform_token, "globex", copy_of(GOOD), authorization_reference=REFERENCE
    )
    target = tmp_path / "config.json"
    target.write_text(json.dumps(GOOD), encoding="utf-8")
    lines: list[str] = []
    reads = ["admin_acme", "20", str(target), "", REFERENCE, "", "21"]
    _run(acme, reads, [COMPANY_PASSWORD], lines)
    text = "\n".join(lines)
    assert any("| acme |" in line for line in lines)
    assert "| globex |" not in text
    assert str(foreign["id"]) not in text
    assert "Diagnóstico general de la plataforma" not in text


def test_an_auditor_cannot_run_an_evaluation_from_the_terminal(acme: Kernel) -> None:
    lines: list[str] = []
    _run(acme, ["auditor_acme", "20", "0"], [COMPANY_PASSWORD], lines)
    assert "Opción no disponible para su cuenta" in lines
    assert "Evaluar un archivo de configuración" not in "\n".join(lines)
    assert acme.audit.events_of_type("audit.run_recorded") == []


def test_invalid_overrides_are_reported_before_anything_is_evaluated(acme: Kernel) -> None:
    lines: list[str] = []
    reads = [ADMIN_USER, "20", "acme", "config.json", "", REFERENCE, "AUT-001"]
    _run(acme, reads, [ADMIN_PASSWORD], lines)
    assert "Error: sobrescritura no válida: use REGLA=valor" in lines
    assert acme.audit.events_of_type("audit.run_recorded") == []


def test_export_and_verify_a_report_from_the_terminal(acme: Kernel, platform_token: str) -> None:
    record = acme.auditing.run_document(
        platform_token, "acme", copy_of(GOOD), authorization_reference=REFERENCE
    )
    lines: list[str] = []
    reads = [ADMIN_USER, "23", "acme", str(record["id"]), "json", "25", "acme"]
    _run(acme, reads, [ADMIN_PASSWORD], lines)
    assert any(line.startswith("Informe: ") and "formato: json" in line for line in lines)
    assert any(line.startswith("Archivo: acme/informe-") for line in lines)
    assert "Verificación correcta" in lines


def _stale_temp(kernel: Kernel) -> Path:
    kernel.context.config_dir.mkdir(parents=True, exist_ok=True)
    stale = kernel.context.config_dir / "sesion.json.tmp"
    stale.write_text("pendiente", encoding="utf-8")
    past = time.time() - 3 * 3600
    os.utime(stale, (past, past))
    return stale


def test_cleanup_shows_the_plan_and_removes_files_after_confirmation_and_reauthentication(
    acme: Kernel,
) -> None:
    stale = _stale_temp(acme)
    lines: list[str] = []
    reads = [ADMIN_USER, "17", "27", "1", "sí"]
    _run(acme, reads, [ADMIN_PASSWORD, ADMIN_PASSWORD], lines)
    assert any(line.startswith("- ") and "sesion.json.tmp" in line for line in lines)
    assert "Eliminados: 1 de 1 planeados" in lines
    assert not stale.exists()


def test_cleanup_without_reauthentication_is_refused_and_keeps_the_file(acme: Kernel) -> None:
    stale = _stale_temp(acme)
    lines: list[str] = []
    _run(acme, [ADMIN_USER, "27", "1", "sí", "0"], [ADMIN_PASSWORD], lines)
    assert "Error: operación crítica: reautentique la sesión" in lines
    assert stale.exists()
    assert acme.audit.events_of_type("maintenance.cleanup_applied") == []


def test_cleanup_cancelled_by_the_user_removes_nothing(acme: Kernel) -> None:
    stale = _stale_temp(acme)
    lines: list[str] = []
    reads = [ADMIN_USER, "17", "27", "1", "no", "0"]
    _run(acme, reads, [ADMIN_PASSWORD, ADMIN_PASSWORD], lines)
    assert "Limpieza cancelada" in lines
    assert stale.exists()
    assert acme.audit.events_of_type("maintenance.cleanup_applied") == []


def test_diagnostics_and_the_rules_catalog_are_shown(acme: Kernel) -> None:
    lines: list[str] = []
    _run(acme, [ADMIN_USER, "26", "28"], [ADMIN_PASSWORD], lines)
    assert any(line.startswith("Estado general:") for line in lines)
    assert "- base_de_datos: ok | integridad verificada" in lines
    rule_lines = [line for line in lines if line.startswith("- AUT-")]
    assert len(rule_lines) == 17
