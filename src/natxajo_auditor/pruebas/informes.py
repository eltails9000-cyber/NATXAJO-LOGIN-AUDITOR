"""Informes de ejecuciones de pruebas HTTP en JSON, CSV, HTML y TXT.

Un informe solo contiene lo que guarda la base de datos: identificadores, códigos, tiempos,
resultados y motivos. No incluye contraseñas, códigos MFA, cookies, tokens ni cuerpos de respuesta,
porque ninguno de esos datos llega a guardarse. La verificación compara el SHA-256 y el tamaño de
cada archivo con lo registrado al exportarlo. Es una huella de integridad, no una firma digital.
"""

from __future__ import annotations

import csv
import html
import io
import json
from collections import Counter
from collections.abc import Mapping
from typing import Any, Final

from natxajo_auditor.core.utilities import csv_cell

FORMATOS: Final[tuple[str, ...]] = ("json", "csv", "html", "txt")
COLUMNAS_CSV: Final[tuple[str, ...]] = (
    "posicion",
    "caso",
    "formulario",
    "tipo",
    "cuenta",
    "resultado",
    "esperado",
    "observado",
    "codigo_http",
    "duracion_ms",
    "motivo",
)
RESULTADOS: Final[tuple[str, ...]] = ("PASS", "FAIL", "BLOCKED", "ERROR", "SKIPPED")
METODOLOGIA: Final = (
    "Cada caso envía una solicitud a un objetivo registrado, con una cuenta sintética. La respuesta se "
    "clasifica (aceptada, rechazada, bloqueada, error o inconsistente) y se compara con lo esperado. "
    "Los límites de solicitudes, concurrencia, pausa y tiempo se aplican antes de cada envío."
)


def renderizar(
    ejecucion: Mapping[str, Any],
    meta: Mapping[str, Any],
    formato: str,
) -> bytes:
    resultados = list(ejecucion.get("resultados", []))
    totales = {nombre: 0 for nombre in RESULTADOS}
    totales.update(Counter(str(r["resultado"]) for r in resultados))
    cabecera = {k: v for k, v in ejecucion.items() if k != "resultados"}
    if formato == "json":
        documento = {
            "metadatos": dict(meta),
            "ejecucion": cabecera,
            "totales": totales,
            "resultados": resultados,
        }
        return json.dumps(documento, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    if formato == "csv":
        return _csv(resultados)
    if formato == "html":
        return _html(cabecera, meta, totales, resultados).encode("utf-8")
    if formato == "txt":
        return _txt(cabecera, meta, totales, resultados).encode("utf-8")
    raise ValueError(f"formato no admitido: {formato}")


def _csv(resultados: list[dict[str, Any]]) -> bytes:
    buffer = io.StringIO()
    escritor = csv.writer(buffer, lineterminator="\n")
    escritor.writerow(COLUMNAS_CSV)
    for r in resultados:
        escritor.writerow(
            [
                csv_cell(r["posicion"]),
                csv_cell(r["caso"]),
                csv_cell(r["formulario"]),
                csv_cell(r["tipo"]),
                csv_cell(r["cuenta"]),
                csv_cell(r["resultado"]),
                csv_cell(r["esperado"]),
                csv_cell(r["observado"]),
                csv_cell(r["codigo_http"]),
                csv_cell(r["duracion_ms"]),
                csv_cell(r["motivo"]),
            ]
        )
    return buffer.getvalue().encode("utf-8")


def _html(
    cabecera: Mapping[str, Any],
    meta: Mapping[str, Any],
    totales: Mapping[str, int],
    resultados: list[dict[str, Any]],
) -> str:
    esc = html.escape
    filas = "".join(
        "<tr>"
        + "".join(
            f"<td>{esc(_texto(r[clave]))}</td>"
            for clave in (
                "posicion",
                "caso",
                "cuenta",
                "resultado",
                "esperado",
                "observado",
                "codigo_http",
                "duracion_ms",
                "motivo",
            )
        )
        + "</tr>"
        for r in resultados
    )
    resumen = "".join(f"<li>{esc(n)}: {totales[n]}</li>" for n in RESULTADOS)
    datos = "".join(
        f"<dt>{esc(clave)}</dt><dd>{esc(_texto(valor))}</dd>" for clave, valor in cabecera.items()
    )
    return (
        '<!doctype html><html lang="es"><head><meta charset="utf-8">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>Pruebas HTTP {esc(_texto(cabecera.get('id')))}</title>"
        "<style>body{font-family:sans-serif;margin:16px}table{border-collapse:collapse}"
        "td,th{border:1px solid #888;padding:4px 6px;font-size:13px}</style></head><body>"
        f"<h1>Informe de pruebas HTTP</h1><p>{esc(METODOLOGIA)}</p>"
        f"<h2>Ejecución</h2><dl>{datos}</dl>"
        f"<h2>Totales</h2><ul>{resumen}</ul>"
        "<h2>Resultados</h2><table><thead><tr><th>#</th><th>Caso</th><th>Cuenta</th>"
        "<th>Resultado</th><th>Esperado</th><th>Observado</th><th>HTTP</th><th>ms</th>"
        f"<th>Motivo</th></tr></thead><tbody>{filas}</tbody></table>"
        f"<p>Generado: {esc(_texto(meta.get('generado_en')))} · "
        f"versión {esc(_texto(meta.get('version_plataforma')))}</p></body></html>"
    )


def _txt(
    cabecera: Mapping[str, Any],
    meta: Mapping[str, Any],
    totales: Mapping[str, int],
    resultados: list[dict[str, Any]],
) -> str:
    lineas = [
        "INFORME DE PRUEBAS HTTP",
        METODOLOGIA,
        "",
        *(f"{clave}: {_texto(valor)}" for clave, valor in cabecera.items()),
        "",
        "TOTALES: " + ", ".join(f"{n}={totales[n]}" for n in RESULTADOS),
        "",
    ]
    for r in resultados:
        lineas.append(
            f"[{r['resultado']}] {r['posicion']:>3} {r['caso']} cuenta={_texto(r['cuenta'])} "
            f"esperado={r['esperado']} observado={_texto(r['observado'])} "
            f"HTTP={_texto(r['codigo_http'])} ms={_texto(r['duracion_ms'])} :: {r['motivo']}"
        )
    lineas.append("")
    lineas.append(
        f"Generado: {_texto(meta.get('generado_en'))} (versión {_texto(meta.get('version_plataforma'))})"
    )
    return "\n".join(lineas) + "\n"


def _texto(valor: object) -> str:
    if valor is None:
        return "no aplica"
    if isinstance(valor, bool):
        return "true" if valor else "false"
    return str(valor)
