"""Servicio de auditoría: evaluaciones con permiso, ámbito de empresa, transacción y auditoría.

Cada operación pasa por el guardián (`OperationGate`) antes de tocar el documento o la base de
datos. El documento se lee dentro de esa operación, así que un usuario sin permiso no llega a abrir
el archivo que indica.

La evaluación solo describe la configuración declarada. No contacta con el objetivo, no envía
solicitudes y no prueba credenciales. El campo de autorización es una referencia escrita que
registra la plataforma. La plataforma no verifica el documento de autorización.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from pathlib import Path

from natxajo_auditor.auditing.catalog import BUILTIN_RULES, SEVERITY_RANK
from natxajo_auditor.auditing.engine import evaluate, resolve_rules
from natxajo_auditor.auditing.loader import read_document
from natxajo_auditor.auditing.results import (
    AUTHORIZATION_MAX,
    AUTHORIZATION_MIN,
    AuditRun,
    to_record,
    validate_run,
)
from natxajo_auditor.auditing.snapshot import parse_snapshot
from natxajo_auditor.auditing.store import MAX_LIST, AuditStore
from natxajo_auditor.core.contracts import (
    AUDIT_READ_PERMISSION,
    AUDIT_RUN_PERMISSION,
    OperationGate,
)
from natxajo_auditor.core.events import COMPANY_ID
from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.utilities import Clock
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database

EVENT_RUN_RECORDED = "audit.run_recorded"


class AuditingService:
    def __init__(
        self,
        *,
        database: Database,
        audit: AuditLog,
        gate: OperationGate,
        clock: Clock,
        engine_version: str,
    ) -> None:
        self._database = database
        self._audit = audit
        self._gate = gate
        self._clock = clock
        self._engine_version = engine_version
        self._store = AuditStore(database)

    def run_document(
        self,
        token: str,
        company_id: str,
        document: object,
        *,
        authorization_reference: str,
        profile: str = "completo",
        overrides: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        """Evalúa un documento ya decodificado. Devuelve el registro de la evaluación."""
        return self._run(
            token,
            company_id,
            lambda: document,
            authorization_reference=authorization_reference,
            profile=profile,
            overrides=overrides,
        )

    def run_file(
        self,
        token: str,
        company_id: str,
        path: Path,
        *,
        authorization_reference: str,
        profile: str = "completo",
        overrides: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        """Evalúa un archivo JSON. El archivo se lee solo después de comprobar el permiso."""
        return self._run(
            token,
            company_id,
            lambda: read_document(path),
            authorization_reference=authorization_reference,
            profile=profile,
            overrides=overrides,
        )

    def history(
        self, token: str, company_id: str | None, *, limit: int = 50
    ) -> list[dict[str, object]]:
        """Evaluaciones de una empresa, o de todas si company_id es None (solo plataforma)."""
        if company_id is not None:
            _check_company(company_id)
        if not 1 <= limit <= MAX_LIST:
            raise ValidationError(f"el número de evaluaciones debe estar entre 1 y {MAX_LIST}")

        def operation() -> list[dict[str, object]]:
            return self._store.list_runs(company_id, limit)

        return self._gate.run(token, AUDIT_READ_PERMISSION, operation, company_id=company_id)

    def get_run(self, token: str, company_id: str, run_id: str) -> dict[str, object]:
        _check_company(company_id)
        _check_run_id(run_id)

        def operation() -> dict[str, object]:
            return to_record(self._store.load(company_id, run_id))

        return self._gate.run(token, AUDIT_READ_PERMISSION, operation, company_id=company_id)

    def rules(self, token: str) -> list[dict[str, object]]:
        """Catálogo de reglas. Son datos públicos de la plataforma: basta una sesión válida."""
        self._gate.username_for(token)
        return [
            {
                "regla": rule.id,
                "titulo": rule.title,
                "ruta": rule.path,
                "gravedad": rule.severity.value,
                "esperado": rule.expected,
                "sobrescribible": rule.overridable is not None,
                "limites": (
                    f"{rule.overridable[0]}-{rule.overridable[1]}"
                    if rule.overridable is not None
                    else ""
                ),
                "recomendacion": rule.recommendation,
            }
            for rule in sorted(
                BUILTIN_RULES, key=lambda item: (-SEVERITY_RANK[item.severity], item.id)
            )
        ]

    def _run(
        self,
        token: str,
        company_id: str,
        load: Callable[[], object],
        *,
        authorization_reference: str,
        profile: str,
        overrides: Mapping[str, object] | None,
    ) -> dict[str, object]:
        _check_company(company_id)
        reference = _check_reference(authorization_reference)

        def operation() -> AuditRun:
            document = load()
            snapshot = parse_snapshot(document)
            requested = dict(overrides or {})
            rules = resolve_rules(profile, requested)
            checked = {rule_id: _as_int(value) for rule_id, value in requested.items()}
            username = self._gate.username_for(token)
            started = self._clock()
            outcomes = evaluate(snapshot, rules)
            run = AuditRun(
                run_id=str(uuid.uuid4()),
                company_id=company_id,
                username=username,
                profile=profile,
                overrides=checked,
                authorization_reference=reference,
                snapshot_sha256=snapshot.canonical_sha256(),
                engine_version=self._engine_version,
                started_at=started,
                finished_at=self._clock(),
                outcomes=outcomes,
            )
            validate_run(run)
            with self._database.transaction() as connection:
                self._store.save(connection, run)
                self._audit.record(
                    EVENT_RUN_RECORDED,
                    {
                        "run_id": run.run_id,
                        "profile": run.profile,
                        "passed": run.passed,
                        "failed": run.failed,
                        "not_evaluable": run.not_evaluable,
                        "risk": run.risk,
                    },
                    connection,
                    company_id=company_id,
                    actor=username,
                )
            return run

        run = self._gate.run(token, AUDIT_RUN_PERMISSION, operation, company_id=company_id)
        return to_record(run)


def _check_company(company_id: str) -> None:
    if not isinstance(company_id, str) or COMPANY_ID.match(company_id) is None:
        raise ValidationError("el identificador de empresa no es válido")


def _check_reference(value: str) -> str:
    text = value.strip()
    if not AUTHORIZATION_MIN <= len(text) <= AUTHORIZATION_MAX or not text.isprintable():
        raise ValidationError(
            "indique la referencia escrita de la autorización "
            f"({AUTHORIZATION_MIN} a {AUTHORIZATION_MAX} caracteres imprimibles)"
        )
    return text


def _check_run_id(run_id: str) -> None:
    try:
        parsed = uuid.UUID(run_id)
    except (ValueError, TypeError):
        raise ValidationError("el identificador de evaluación no es válido") from None
    if str(parsed) != run_id:
        raise ValidationError("el identificador de evaluación no es válido")


def _as_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError("el umbral debe ser un entero")
    return value
