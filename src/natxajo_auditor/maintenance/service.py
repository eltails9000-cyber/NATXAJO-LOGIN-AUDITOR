"""Servicio de mantenimiento: diagnóstico y limpieza de temporales, siempre con permiso.

- El diagnóstico y el plan de limpieza solo leen. Son operaciones de plataforma.
- Borrar temporales es una operación crítica del guardián: exige confirmación explícita y
  reautenticación reciente de la sesión.
"""

from __future__ import annotations

import sqlite3
import sys
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path
from typing import Final

from natxajo_auditor.core.contracts import (
    CLEANUP_PERMISSION,
    DIAGNOSTIC_PERMISSION,
    PLATFORM_COMPANY,
    OperationGate,
)
from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.utilities import Clock
from natxajo_auditor.maintenance.cleanup import apply_cleanup, plan_cleanup
from natxajo_auditor.maintenance.diagnostics import Check, collect_checks, overall
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.backups import BackupManager
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.outbox import EventOutbox

EVENT_CLEANUP: Final = "maintenance.cleanup_applied"
MIN_AGE_HOURS: Final = 1
MAX_AGE_HOURS: Final = 24 * 365


class MaintenanceService:
    def __init__(
        self,
        *,
        database: Database,
        outbox: EventOutbox,
        backups: BackupManager,
        audit: AuditLog,
        gate: OperationGate,
        clock: Clock,
        managed_dirs: Sequence[Path],
        python_version: tuple[int, int, int] | None = None,
        sqlite_version: tuple[int, int, int] | None = None,
    ) -> None:
        self._database = database
        self._outbox = outbox
        self._backups = backups
        self._audit = audit
        self._gate = gate
        self._clock = clock
        self._managed = tuple(managed_dirs)
        info = sys.version_info
        self._python = python_version or (info.major, info.minor, info.micro)
        self._sqlite = sqlite_version or sqlite3.sqlite_version_info

    def diagnose(self, token: str) -> dict[str, object]:
        def operation() -> dict[str, object]:
            checks = self._checks()
            return {
                "estado": overall(checks).value,
                "comprobaciones": [_check_record(check) for check in checks],
            }

        return self._gate.run(token, DIAGNOSTIC_PERMISSION, operation, company_id=None)

    def plan_cleanup(self, token: str, *, older_than_hours: int = 24) -> list[str]:
        """Temporales que la limpieza borraría. No borra nada."""
        hours = _check_hours(older_than_hours)

        def operation() -> list[str]:
            paths = plan_cleanup(
                self._managed, now=self._clock(), older_than=timedelta(hours=hours)
            )
            return [str(path) for path in paths]

        return self._gate.run(token, DIAGNOSTIC_PERMISSION, operation, company_id=None)

    def apply_cleanup(
        self, token: str, *, older_than_hours: int = 24, confirmed: bool
    ) -> dict[str, object]:
        hours = _check_hours(older_than_hours)

        def operation() -> dict[str, object]:
            username = self._gate.username_for(token)
            paths = plan_cleanup(
                self._managed, now=self._clock(), older_than=timedelta(hours=hours)
            )
            removed = apply_cleanup(paths, self._managed)
            self._audit.record(
                EVENT_CLEANUP,
                {"removed": removed},
                company_id=PLATFORM_COMPANY,
                actor=username,
            )
            return {"planeados": len(paths), "eliminados": removed}

        return self._gate.run(
            token, CLEANUP_PERMISSION, operation, confirmed=confirmed, company_id=None
        )

    def _checks(self) -> list[Check]:
        return collect_checks(
            database=self._database,
            outbox=self._outbox,
            backups=self._backups,
            managed_dirs=self._managed,
            python_version=self._python,
            sqlite_version=self._sqlite,
        )


def _check_record(check: Check) -> dict[str, object]:
    return {"nombre": check.name, "estado": check.status.value, "detalle": check.detail}


def _check_hours(hours: int) -> int:
    if not MIN_AGE_HOURS <= hours <= MAX_AGE_HOURS:
        raise ValidationError(
            f"la antigüedad debe estar entre {MIN_AGE_HOURS} y {MAX_AGE_HOURS} horas"
        )
    return hours
