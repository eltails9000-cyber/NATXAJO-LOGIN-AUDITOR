"""Persistencia de objetivos, ejecuciones, resultados y exportaciones (migración 14).

Abrir una ejecución y su evento de auditoría, o cerrarla con sus resultados, se hace en una sola
transacción. Las tablas son añadir-solo: los disparadores impiden modificar o borrar lo ya guardado.
Una ejecución se cierra una única vez, y los resultados solo se insertan mientras está en curso.
"""

from __future__ import annotations

import sqlite3
from typing import Final

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.pruebas.modelo import ResultadoCaso
from natxajo_auditor.storage.database import Database

_RESULTADO_CAMPOS: Final = (
    "position, case_id, form_id, form_type, account, outcome, expected, observed, "
    "http_status, duration_ms, reason"
)


class RepositorioPruebas:
    def __init__(self, database: Database) -> None:
        self._db = database

    def objetivos(self) -> list[dict[str, object]]:
        filas = self._db.fetchall(
            "SELECT origin, registered_at, registered_by FROM http_targets ORDER BY origin"
        )
        return [
            {"origen": origen, "registrado_en": momento, "registrado_por": usuario}
            for origen, momento, usuario in filas
        ]

    def objetivos_registrados(self) -> frozenset[str]:
        return frozenset(
            origen for (origen,) in self._db.fetchall("SELECT origin FROM http_targets")
        )

    def es_cuenta_de_plataforma(self, usuario: str) -> bool:
        """Las cuentas de la plataforma nunca se usan como cuentas sintéticas de prueba."""
        return bool(self._db.fetchall("SELECT 1 FROM accounts WHERE username = ?", (usuario,)))

    def registrar_objetivo(
        self,
        conexion: sqlite3.Connection,
        origen: str,
        usuario: str,
        momento: str,
    ) -> None:
        existe = conexion.execute("SELECT 1 FROM http_targets WHERE origin = ?", (origen,))
        if existe.fetchone() is not None:
            raise ValidationError("el objetivo ya está registrado")
        conexion.execute(
            "INSERT INTO http_targets (origin, registered_at, registered_by) VALUES (?, ?, ?)",
            (origen, momento, usuario),
        )

    def abrir_ejecucion(
        self,
        conexion: sqlite3.Connection,
        *,
        run_id: str,
        suite: str,
        origen: str,
        esquema_sha256: str,
        usuario: str,
        iniciado_en: str,
        casos: int,
    ) -> None:
        conexion.execute(
            "INSERT INTO http_runs (id, suite, origin, schema_sha256, requested_by, started_at, "
            "finished_at, status, cases, requests) VALUES (?, ?, ?, ?, ?, ?, NULL, 'en_curso', ?, 0)",
            (run_id, suite, origen, esquema_sha256, usuario, iniciado_en, casos),
        )

    def registrar_resultado(
        self,
        conexion: sqlite3.Connection,
        run_id: str,
        resultado: ResultadoCaso,
    ) -> None:
        """Añade un resultado a una ejecución en curso. La clave (ejecución, posición) impide duplicarlo."""
        conexion.execute(
            f"INSERT INTO http_results ({_RESULTADO_CAMPOS}, run_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                resultado.posicion,
                resultado.caso_id,
                resultado.formulario_id,
                resultado.tipo,
                resultado.cuenta,
                resultado.resultado.value,
                resultado.esperado,
                resultado.observado,
                resultado.codigo_http,
                resultado.duracion_ms,
                resultado.motivo,
                run_id,
            ),
        )

    def progreso(self, conexion: sqlite3.Connection, run_id: str, solicitudes: int) -> None:
        """Guarda cuántas solicitudes llevan enviadas. Así una ejecución interrumpida conserva su avance."""
        conexion.execute(
            "UPDATE http_runs SET requests = ? WHERE id = ? AND status = 'en_curso'",
            (solicitudes, run_id),
        )

    def conteo_resultados(self, conexion: sqlite3.Connection, run_id: str) -> dict[str, int]:
        filas = conexion.execute(
            "SELECT outcome, COUNT(*) FROM http_results WHERE run_id = ? GROUP BY outcome",
            (run_id,),
        ).fetchall()
        return {resultado: cantidad for resultado, cantidad in filas}

    def cerrar_ejecucion(
        self,
        conexion: sqlite3.Connection,
        *,
        run_id: str,
        estado: str,
        terminado_en: str,
        solicitudes: int,
        motivo: str | None,
    ) -> None:
        """Cierra una ejecución en curso. El disparador impide cerrarla dos veces."""
        conexion.execute(
            "UPDATE http_runs SET status = ?, finished_at = ?, requests = ?, close_reason = ? "
            "WHERE id = ?",
            (estado, terminado_en, solicitudes, motivo, run_id),
        )

    def ejecuciones_en_curso(self) -> list[tuple[str, int]]:
        """Ejecuciones sin cerrar, con las solicitudes registradas hasta su último resultado."""
        return [
            (id_, solicitudes)
            for id_, solicitudes in self._db.fetchall(
                "SELECT id, requests FROM http_runs WHERE status = 'en_curso' ORDER BY started_at"
            )
        ]

    def ejecuciones(self, limite: int) -> list[dict[str, object]]:
        filas = self._db.fetchall(
            "SELECT id, suite, origin, requested_by, started_at, finished_at, status, cases, requests "
            "FROM http_runs ORDER BY started_at DESC, id LIMIT ?",
            (limite,),
        )
        return [_ejecucion_resumen(fila) for fila in filas]

    def ejecucion(self, run_id: str) -> dict[str, object] | None:
        # Huella y motivo de cierre van al final: _ejecucion_resumen lee las nueve primeras columnas.
        cabecera = self._db.fetchall(
            "SELECT id, suite, origin, requested_by, started_at, finished_at, status, cases, "
            "requests, schema_sha256, close_reason FROM http_runs WHERE id = ?",
            (run_id,),
        )
        if not cabecera:
            return None
        filas = self._db.fetchall(
            f"SELECT {_RESULTADO_CAMPOS} FROM http_results WHERE run_id = ? ORDER BY position",
            (run_id,),
        )
        ejecucion = _ejecucion_resumen(cabecera[0])
        ejecucion["esquema_sha256"] = cabecera[0][9]
        ejecucion["motivo_cierre"] = cabecera[0][10]
        ejecucion["resultados"] = [_resultado_registro(fila) for fila in filas]
        return ejecucion

    def registrar_exportacion(
        self,
        conexion: sqlite3.Connection,
        *,
        export_id: str,
        run_id: str,
        formato: str,
        usuario: str,
        ruta_relativa: str,
        sha256: str,
        tamano: int,
        creado_en: str,
    ) -> None:
        conexion.execute(
            "INSERT INTO http_exports (id, run_id, format, requested_by, relative_path, sha256, "
            "size_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (export_id, run_id, formato, usuario, ruta_relativa, sha256, tamano, creado_en),
        )

    def exportaciones(self) -> list[dict[str, object]]:
        filas = self._db.fetchall(
            "SELECT id, run_id, format, requested_by, relative_path, sha256, size_bytes, created_at "
            "FROM http_exports ORDER BY created_at, id"
        )
        return [
            {
                "id": id_,
                "run_id": run_id,
                "formato": formato,
                "solicitado_por": usuario,
                "ruta": ruta,
                "sha256": sha256,
                "tamano_bytes": tamano,
                "creado_en": creado_en,
            }
            for id_, run_id, formato, usuario, ruta, sha256, tamano, creado_en in filas
        ]


def _ejecucion_resumen(fila: tuple[object, ...]) -> dict[str, object]:
    id_, suite, origen, usuario, iniciado, terminado, estado, casos, solicitudes = fila[:9]
    return {
        "id": id_,
        "suite": suite,
        "origen": origen,
        "solicitado_por": usuario,
        "iniciado_en": iniciado,
        "terminado_en": terminado,
        "estado": estado,
        "casos": casos,
        "solicitudes": solicitudes,
    }


def _resultado_registro(fila: tuple[object, ...]) -> dict[str, object]:
    (
        posicion,
        caso,
        formulario,
        tipo,
        cuenta,
        resultado,
        esperado,
        observado,
        codigo,
        duracion,
        motivo,
    ) = fila
    return {
        "posicion": posicion,
        "caso": caso,
        "formulario": formulario,
        "tipo": tipo,
        "cuenta": cuenta,
        "resultado": resultado,
        "esperado": esperado,
        "observado": observado,
        "codigo_http": codigo,
        "duracion_ms": duracion,
        "motivo": motivo,
    }
