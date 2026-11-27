"""Acciones de terminal de auditoría, informes y mantenimiento.

Cada acción pide los datos, llama al servicio del núcleo y muestra el resultado. Los servicios
aplican el guardián (sesión, permiso, empresa, confirmación y reautenticación) y registran sus
operaciones, así que estas acciones no repiten esas comprobaciones. Solo deciden qué empresa se
pide: una cuenta de la plataforma la indica y una cuenta de empresa usa la suya.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from natxajo_auditor.core.contracts import PLATFORM_COMPANY
from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.interfaces.terminal.console import Console, confirm

PROFILES = ("completo", "critico")
REPORT_FORMATS = ("json", "csv", "html", "txt")
LIST_LIMIT = 20
DEFAULT_CLEANUP_HOURS = 24
NO_VALUE = "sin valor"


def _ask(console: Console, prompt: str) -> str:
    value = console.read(prompt).strip()
    if not value:
        raise ValidationError("este dato no puede estar vacío")
    return value


def _company_required(console: Console) -> str:
    if console.company != PLATFORM_COMPANY:
        return console.company
    return _ask(console, "Identificador de la empresa: ")


def _company_optional(console: Console) -> str | None:
    """Una cuenta de la plataforma puede ver todas las empresas dejando el dato en blanco."""
    if console.company != PLATFORM_COMPANY:
        return console.company
    return console.read("Empresa (Enter para todas): ").strip() or None


def _path(console: Console) -> Path:
    # Las rutas copiadas como «Copiar como ruta» en Windows llegan entre comillas.
    text = _ask(console, "Ruta del archivo JSON de configuración: ").strip('"').strip()
    if not text:
        raise ValidationError("indique la ruta del archivo")
    return Path(text)


def _overrides(text: str) -> dict[str, object]:
    """Lee sobrescrituras con el formato REGLA=valor, separadas por comas. Solo admite enteros."""
    result: dict[str, object] = {}
    for part in text.split(","):
        item = part.strip()
        if not item:
            continue
        rule_id, separator, value = item.partition("=")
        if not separator:
            raise ValidationError("sobrescritura no válida: use REGLA=valor")
        try:
            result[rule_id.strip()] = int(value.strip())
        except ValueError as exc:
            raise ValidationError("el valor de una sobrescritura debe ser un entero") from exc
    return result


def _display(value: object) -> str:
    return NO_VALUE if value is None else str(value)


def _show_summary(console: Console, record: dict[str, object]) -> None:
    summary = cast(dict[str, object], record["resumen"])
    console.write(f"Evaluación: {record['id']}")
    console.write(
        f"Empresa: {record['empresa']} | perfil: {record['perfil']} | inicio: {record['inicio']}"
    )
    console.write(
        f"Cumple: {summary['cumple']} | No cumple: {summary['no_cumple']} "
        f"| No evaluable: {summary['no_evaluable']} | Riesgo más alto: {summary['riesgo']}"
    )


def _show_findings(console: Console, record: dict[str, object], *, only_failed: bool) -> None:
    for finding in cast(list[dict[str, object]], record["hallazgos"]):
        status = finding["estado"]
        if only_failed and status == "cumple":
            continue
        console.write(
            f"- {finding['regla']} | {status} | {finding['gravedad']} | {finding['titulo']}"
        )
        if status != "cumple":
            console.write(
                f"    observado: {_display(finding['valor_observado'])} "
                f"| esperado: {finding['valor_esperado']}"
            )
            console.write(f"    recomendación: {finding['recomendacion']}")


def run_audit_from_file(console: Console) -> None:
    company = _company_required(console)
    path = _path(console)
    profile = console.read("Perfil (completo o critico) [completo]: ").strip().lower()
    profile = profile or "completo"
    if profile not in PROFILES:
        raise ValidationError("perfil no válido: use completo o critico")
    reference = _ask(console, "Referencia de la autorización escrita: ")
    overrides = _overrides(
        console.read("Sobrescrituras REGLA=valor separadas por comas (Enter para ninguna): ")
    )
    record = console.kernel.auditing.run_file(
        console.token,
        company,
        path,
        authorization_reference=reference,
        profile=profile,
        overrides=overrides,
    )
    _show_summary(console, record)
    _show_findings(console, record, only_failed=True)


def audit_history(console: Console) -> None:
    company = _company_optional(console)
    runs = console.kernel.auditing.history(console.token, company, limit=LIST_LIMIT)
    if not runs:
        console.write("Sin evaluaciones registradas")
        return
    for run in runs:
        console.write(
            f"- {run['id']} | {run['inicio']} | {run['empresa']} | {run['perfil']} "
            f"| riesgo: {run['riesgo']} | no cumple: {run['no_cumple']}"
        )


def audit_view(console: Console) -> None:
    company = _company_required(console)
    run_id = _ask(console, "Identificador de la evaluación: ")
    record = console.kernel.auditing.get_run(console.token, company, run_id)
    _show_summary(console, record)
    console.write(f"Huella de la configuración (SHA-256): {record['huella_configuracion']}")
    console.write(f"Referencia de autorización: {record['autorizacion']}")
    _show_findings(console, record, only_failed=False)


def report_export(console: Console) -> None:
    company = _company_required(console)
    run_id = _ask(console, "Identificador de la evaluación: ")
    fmt = _ask(console, f"Formato ({', '.join(REPORT_FORMATS)}): ").lower()
    record = console.kernel.reports.export(console.token, company, run_id, fmt)
    console.write(
        f"Informe: {record['id']} | formato: {record['formato']} | {record['bytes']} bytes"
    )
    console.write(f"Archivo: {record['ruta']}")
    console.write(f"SHA-256: {record['sha256']}")


def report_history(console: Console) -> None:
    company = _company_optional(console)
    reports = console.kernel.reports.history(console.token, company, limit=LIST_LIMIT)
    if not reports:
        console.write("Sin informes exportados")
        return
    for report in reports:
        console.write(
            f"- {report['id']} | {report['creado']} | {report['empresa']} "
            f"| {report['formato']} | evaluación: {report['evaluacion']} | {report['ruta']}"
        )


def report_verify(console: Console) -> None:
    company = _company_required(console)
    results = console.kernel.reports.verify(console.token, company)
    if not results:
        console.write("No hay informes registrados ni archivos sin registro")
        return
    problems = 0
    for item in results:
        state = item["estado"]
        signature = item["firma"]
        # Un informe sin firma (anterior a la firma) no es un problema; una firma inválida sí.
        if state != "correcto" or signature in ("firma_no_valida", "no_legible"):
            problems += 1
        console.write(f"- {item['ruta']} | {state} | firma: {signature}")
    console.write(
        "Verificación correcta" if problems == 0 else f"Problemas encontrados: {problems}"
    )


def maintenance_diagnostics(console: Console) -> None:
    report = console.kernel.maintenance.diagnose(console.token)
    console.write(f"Estado general: {report['estado']}")
    for check in cast(list[dict[str, str]], report["comprobaciones"]):
        console.write(f"- {check['nombre']}: {check['estado']} | {check['detalle']}")


def _cleanup_hours(console: Console) -> int:
    text = console.read(f"Antigüedad mínima en horas [{DEFAULT_CLEANUP_HOURS}]: ").strip()
    if not text:
        return DEFAULT_CLEANUP_HOURS
    try:
        return int(text)
    except ValueError as exc:
        raise ValidationError("la antigüedad debe ser un número entero de horas") from exc


def maintenance_cleanup(console: Console) -> None:
    """Muestra primero el plan (sin borrar nada) y borra solo tras confirmarlo.

    La confirmación de esta acción la pide la terminal; la reautenticación reciente la exige el
    servicio al aplicar la limpieza.
    """
    hours = _cleanup_hours(console)
    planned = console.kernel.maintenance.plan_cleanup(console.token, older_than_hours=hours)
    if not planned:
        console.write(f"No hay temporales de más de {hours} hora(s)")
        return
    console.write(f"Temporales que se eliminarían ({len(planned)}):")
    for path in planned:
        console.write(f"- {path}")
    if not confirm(console):
        console.write("Limpieza cancelada")
        return
    result = console.kernel.maintenance.apply_cleanup(
        console.token, older_than_hours=hours, confirmed=True
    )
    console.write(f"Eliminados: {result['eliminados']} de {result['planeados']} planeados")
    if result["fallidos"]:
        console.write(
            f"No se pudieron eliminar {result['fallidos']} archivo(s): revise sus permisos"
        )


def rules_list(console: Console) -> None:
    for rule in console.kernel.auditing.rules(console.token):
        limits = f" | sobrescribible: {rule['limites']}" if rule["sobrescribible"] else ""
        console.write(
            f"- {rule['regla']} | {rule['gravedad']} | {rule['titulo']} "
            f"| esperado: {rule['esperado']}{limits}"
        )
