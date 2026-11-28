"""Formatos de informe (JSON, CSV, HTML y TXT) generados a partir de una evaluación.

Los cuatro formatos muestran el mismo contenido. Reglas de seguridad:
- HTML escapa cada valor y no carga recursos externos.
- CSV neutraliza las celdas que empiezan por un carácter de fórmula, para que una hoja de cálculo
  no las ejecute.
- Ningún formato incluye datos que no estén en la evaluación. Los documentos de configuración no
  admiten secretos (ver auditing/snapshot.py), así que tampoco pueden aparecer en un informe.
"""

from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import dataclass

from natxajo_auditor.auditing.results import AuditRun, to_record
from natxajo_auditor.core.utilities import csv_cell

FORMATS: tuple[str, ...] = ("json", "csv", "html", "txt")

METHODOLOGY = (
    "Evaluación sin conexión de la configuración declarada en el documento de entrada. "
    "Ninguna solicitud se envía al sistema evaluado, no se prueban credenciales y no se verifica "
    "que la configuración esté aplicada en el sistema real. Cada regla compara un valor declarado "
    "con su umbral vigente: el del catálogo, o el que fija el perfil dentro de los límites de la "
    "regla. El umbral aplicado figura en la columna de valor esperado."
)
CSV_HEADER: tuple[str, ...] = (
    "regla",
    "titulo",
    "ruta",
    "estado",
    "gravedad",
    "valor_observado",
    "valor_esperado",
    "recomendacion",
)


@dataclass(frozen=True)
class ReportMeta:
    report_id: str
    generated_at: str
    platform_version: str
    username: str


def render(run: AuditRun, meta: ReportMeta, fmt: str) -> bytes:
    if fmt == "json":
        text = _json(run, meta)
    elif fmt == "csv":
        text = _csv(run)
    elif fmt == "html":
        text = _html(run, meta)
    elif fmt == "txt":
        text = _txt(run, meta)
    else:
        raise ValueError(f"formato no soportado: {fmt}")
    return text.encode("utf-8")


def _header(meta: ReportMeta) -> dict[str, str]:
    return {
        "id": meta.report_id,
        "generado": meta.generated_at,
        "version_plataforma": meta.platform_version,
        "generado_por": meta.username,
        "tipo": "auditoria_de_configuracion",
        "metodologia": METHODOLOGY,
    }


def _json(run: AuditRun, meta: ReportMeta) -> str:
    document: dict[str, object] = {"informe": _header(meta), "evaluacion": to_record(run)}
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _csv(run: AuditRun) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_HEADER)
    for outcome in run.outcomes:
        writer.writerow(
            [
                csv_cell(outcome.rule_id),
                csv_cell(outcome.title),
                csv_cell(outcome.path),
                csv_cell(outcome.status.value),
                csv_cell(outcome.severity.value),
                csv_cell(outcome.observed),
                csv_cell(outcome.expected),
                csv_cell(outcome.recommendation),
            ]
        )
    return buffer.getvalue()


def _html(run: AuditRun, meta: ReportMeta) -> str:
    esc = html.escape
    rows = "\n".join(
        "      <tr>"
        f"<td>{esc(o.rule_id)}</td>"
        f"<td>{esc(o.title)}</td>"
        f"<td>{esc(o.status.value)}</td>"
        f"<td>{esc(o.severity.value)}</td>"
        f"<td>{esc(_text(o.observed))}</td>"
        f"<td>{esc(o.expected)}</td>"
        f"<td>{esc(o.recommendation)}</td>"
        "</tr>"
        for o in run.outcomes
    )
    header = _header(meta)
    return (
        "<!doctype html>\n"
        '<html lang="es">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>Informe {esc(run.run_id)}</title>\n"
        "<style>\n"
        "body{font-family:system-ui,sans-serif;margin:16px;color:#1d1d1f;background:#fff}\n"
        "table{border-collapse:collapse;width:100%}\n"
        "th,td{border:1px solid #c7c7cc;padding:6px;text-align:left;vertical-align:top}\n"
        "th{background:#f2f2f7}\n"
        "</style>\n</head>\n<body>\n"
        "<h1>Informe de auditoría de configuración</h1>\n"
        "<dl>\n"
        f"<dt>Identificador</dt><dd>{esc(run.run_id)}</dd>\n"
        f"<dt>Empresa</dt><dd>{esc(run.company_id)}</dd>\n"
        f"<dt>Perfil</dt><dd>{esc(run.profile)}</dd>\n"
        f"<dt>Autorización (referencia)</dt><dd>{esc(run.authorization_reference)}</dd>\n"
        f"<dt>Huella del documento</dt><dd>{esc(run.snapshot_sha256)}</dd>\n"
        f"<dt>Inicio</dt><dd>{esc(header['generado'])}</dd>\n"
        f"<dt>Versión de la plataforma</dt><dd>{esc(meta.platform_version)}</dd>\n"
        "</dl>\n"
        f"<p>{esc(METHODOLOGY)}</p>\n"
        "<h2>Resumen</h2>\n"
        f"<p>Cumple: {run.passed} · No cumple: {run.failed} · "
        f"No evaluable: {run.not_evaluable} · Riesgo más alto: {esc(run.risk)}</p>\n"
        "<h2>Resultados</h2>\n<table>\n<thead><tr>"
        "<th>Regla</th><th>Título</th><th>Estado</th><th>Gravedad</th>"
        "<th>Valor observado</th><th>Valor esperado</th><th>Recomendación</th>"
        "</tr></thead>\n<tbody>\n"
        f"{rows}\n"
        "</tbody>\n</table>\n</body>\n</html>\n"
    )


def _txt(run: AuditRun, meta: ReportMeta) -> str:
    summary = (
        f"Resumen: cumple {run.passed}, no cumple {run.failed}, "
        f"no evaluable {run.not_evaluable}, riesgo más alto {run.risk}"
    )
    lines = [
        "INFORME DE AUDITORÍA DE CONFIGURACIÓN",
        f"Identificador: {run.run_id}",
        f"Empresa: {run.company_id}",
        f"Perfil: {run.profile}",
        f"Autorización (referencia): {run.authorization_reference}",
        f"Huella del documento: {run.snapshot_sha256}",
        f"Generado: {meta.generated_at} por {meta.username}",
        f"Versión de la plataforma: {meta.platform_version}",
        "",
        METHODOLOGY,
        "",
        summary,
        "",
    ]
    for outcome in run.outcomes:
        lines.append(
            f"[{outcome.status.value}] {outcome.rule_id} ({outcome.severity.value}) {outcome.title}"
        )
        lines.append(f"    valor observado: {_text(outcome.observed)}")
        lines.append(f"    valor esperado: {outcome.expected}")
        lines.append(f"    recomendación: {outcome.recommendation}")
    return "\n".join(lines) + "\n"


def _text(value: object) -> str:
    if value is None:
        return "no configurado"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)
