"""Formato de la salida de la CLI: tablas de texto, pares clave-valor y totales por resultado.

Funciones puras. No deciden permisos ni interpretan pruebas: solo dan forma a lo que el motor
devuelve. Los valores nulos se muestran como «-» y los booleanos como «sí» o «no».
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Final

RESULTADOS: Final[tuple[str, ...]] = ("PASS", "FAIL", "BLOCKED", "ERROR", "SKIPPED")


def tabla(encabezados: Sequence[str], filas: Sequence[Sequence[object]]) -> str:
    celdas = [[_celda(valor) for valor in fila] for fila in filas]
    anchos = [len(texto) for texto in encabezados]
    for fila in celdas:
        for indice, texto in enumerate(fila):
            anchos[indice] = max(anchos[indice], len(texto))

    def linea(valores: Sequence[str]) -> str:
        return "  ".join(v.ljust(anchos[i]) for i, v in enumerate(valores)).rstrip()

    lineas = [linea(list(encabezados)), linea(["-" * ancho for ancho in anchos])]
    lineas.extend(linea(fila) for fila in celdas)
    return "\n".join(lineas)


def pares(datos: Mapping[str, object]) -> str:
    ancho = max((len(clave) for clave in datos), default=0)
    return "\n".join(f"{clave.ljust(ancho)}  {_celda(valor)}" for clave, valor in datos.items())


def totales(resultados: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    cuenta = dict.fromkeys(RESULTADOS, 0)
    for resultado in resultados:
        clave = str(resultado["resultado"])
        cuenta[clave] = cuenta.get(clave, 0) + 1
    return cuenta


def resumen_ejecucion(ejecucion: Mapping[str, Any]) -> str:
    cuenta = totales(ejecucion["resultados"])
    cabecera = (
        f"Ejecución {ejecucion['id']} · suite {ejecucion['suite']} · "
        f"estado {ejecucion['estado']} · solicitudes {ejecucion['solicitudes']}"
    )
    recuento = "  ".join(f"{nombre}={cuenta[nombre]}" for nombre in RESULTADOS)
    return f"{cabecera}\n{recuento}"


def tabla_resultados(resultados: Sequence[Mapping[str, Any]]) -> str:
    return tabla(
        ("#", "caso", "cuenta", "resultado", "esperado", "observado", "HTTP", "ms", "motivo"),
        [
            (
                r["posicion"],
                r["caso"],
                r["cuenta"],
                r["resultado"],
                r["esperado"],
                r["observado"],
                r["codigo_http"],
                r["duracion_ms"],
                r["motivo"],
            )
            for r in resultados
        ],
    )


def hay_fallos(resultados: Sequence[Mapping[str, Any]]) -> bool:
    return any(str(r["resultado"]) in ("FAIL", "ERROR") for r in resultados)


def _celda(valor: object) -> str:
    if valor is None:
        return "-"
    if isinstance(valor, bool):
        return "sí" if valor else "no"
    if isinstance(valor, (Mapping, list, tuple)):
        return json.dumps(valor, ensure_ascii=False, sort_keys=True)
    return str(valor)
