"""Persistencia de evaluaciones: guardar, listar y cargar con comprobación de integridad.

Las evaluaciones y sus hallazgos son inmutables (disparadores de la migración 10). Guardar
ocurre dentro de la transacción que la auditoría necesita, así que una evaluación sin su registro
de auditoría no queda en la base de datos.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from natxajo_auditor.auditing.catalog import Severity, Status
from natxajo_auditor.auditing.engine import Outcome
from natxajo_auditor.auditing.results import AuditRun, validate_run
from natxajo_auditor.auditing.snapshot import Scalar
from natxajo_auditor.core.exceptions import StorageError, ValidationError
from natxajo_auditor.core.utilities import from_iso, to_iso
from natxajo_auditor.storage.database import Database

MAX_LIST = 500


class AuditStore:
    def __init__(self, database: Database) -> None:
        self._database = database

    def save(self, connection: sqlite3.Connection, run: AuditRun) -> None:
        """Inserta la evaluación y sus hallazgos dentro de la transacción recibida."""
        connection.execute(
            "INSERT INTO audit_runs (id, company_id, username, profile, overrides, "
            "authorization_reference, snapshot_sha256, engine_version, started_at, finished_at, "
            "passed, failed, not_evaluable, risk) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run.run_id,
                run.company_id,
                run.username,
                run.profile,
                json.dumps(dict(sorted(run.overrides.items()))),
                run.authorization_reference,
                run.snapshot_sha256,
                run.engine_version,
                to_iso(run.started_at),
                to_iso(run.finished_at),
                run.passed,
                run.failed,
                run.not_evaluable,
                run.risk,
            ),
        )
        for outcome in run.outcomes:
            connection.execute(
                "INSERT INTO audit_findings (run_id, rule_id, title, path, status, severity, "
                "observed, expected, recommendation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run.run_id,
                    outcome.rule_id,
                    outcome.title,
                    outcome.path,
                    outcome.status.value,
                    outcome.severity.value,
                    None if outcome.observed is None else json.dumps(outcome.observed),
                    outcome.expected,
                    outcome.recommendation,
                ),
            )

    def list_runs(self, company_id: str | None, limit: int) -> list[dict[str, object]]:
        """Resúmenes de evaluaciones, la más reciente primero. Sin company_id, todas."""
        if not 1 <= limit <= MAX_LIST:
            raise ValidationError(f"el número de evaluaciones debe estar entre 1 y {MAX_LIST}")
        where, params = _scope_clause(company_id)
        rows = self._database.fetchall(
            "SELECT id, company_id, username, profile, authorization_reference, started_at, "
            "passed, failed, not_evaluable, risk FROM audit_runs "
            f"{where} ORDER BY started_at DESC, id DESC LIMIT ?",
            (*params, limit),
        )
        return [
            {
                "id": row[0],
                "empresa": row[1],
                "usuario": row[2],
                "perfil": row[3],
                "autorizacion": row[4],
                "inicio": row[5],
                "cumple": row[6],
                "no_cumple": row[7],
                "no_evaluable": row[8],
                "riesgo": row[9],
            }
            for row in rows
        ]

    def load(self, company_id: str, run_id: str) -> AuditRun:
        """Carga una evaluación de la empresa indicada y comprueba que sigue siendo coherente."""
        rows = self._database.fetchall(
            "SELECT id, company_id, username, profile, overrides, authorization_reference, "
            "snapshot_sha256, engine_version, started_at, finished_at, passed, failed, "
            "not_evaluable, risk FROM audit_runs WHERE id = ? AND company_id = ?",
            (run_id, company_id),
        )
        if not rows:
            # Igual para una evaluación inexistente que para una de otra empresa.
            raise ValidationError("evaluación no encontrada")
        row = rows[0]
        findings = self._database.fetchall(
            "SELECT rule_id, title, path, status, severity, observed, expected, recommendation "
            "FROM audit_findings WHERE run_id = ?",
            (run_id,),
        )
        run = AuditRun(
            run_id=str(row[0]),
            company_id=str(row[1]),
            username=str(row[2]),
            profile=str(row[3]),
            overrides=_overrides(row[4]),
            authorization_reference=str(row[5]),
            snapshot_sha256=str(row[6]),
            engine_version=str(row[7]),
            started_at=_moment(row[8]),
            finished_at=_moment(row[9]),
            outcomes=tuple(_outcome(finding) for finding in findings),
        )
        try:
            validate_run(run)
        except ValidationError as exc:
            raise StorageError(f"registro de evaluación inconsistente: {exc}") from None
        stored = (row[10], row[11], row[12], row[13])
        if stored != (run.passed, run.failed, run.not_evaluable, run.risk):
            raise StorageError("registro de evaluación inconsistente: los totales no coinciden")
        return run


def _scope_clause(company_id: str | None) -> tuple[str, tuple[Any, ...]]:
    if company_id is None:
        return "", ()
    return "WHERE company_id = ?", (company_id,)


def _overrides(text: object) -> dict[str, int]:
    data = json.loads(str(text))
    if not isinstance(data, dict) or not all(
        isinstance(value, int) and not isinstance(value, bool) for value in data.values()
    ):
        raise StorageError("registro de evaluación inconsistente: sobrescrituras no válidas")
    return {str(key): int(value) for key, value in data.items()}


def _moment(text: object) -> datetime:
    parsed = from_iso(str(text))
    if parsed is None:
        raise StorageError("registro de evaluación inconsistente: fecha no válida")
    return parsed


def _outcome(row: tuple[Any, ...]) -> Outcome:
    observed: Scalar = None if row[5] is None else json.loads(str(row[5]))
    return Outcome(
        rule_id=str(row[0]),
        title=str(row[1]),
        path=str(row[2]),
        status=Status(str(row[3])),
        severity=Severity(str(row[4])),
        observed=observed,
        expected=str(row[6]),
        recommendation=str(row[7]),
    )
