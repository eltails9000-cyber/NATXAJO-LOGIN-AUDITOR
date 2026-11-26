"""Exportación de informes: permiso, ámbito, escritura atómica, registro y verificación.

Un informe se escribe en `reports/<empresa>/`, con un nombre que genera la plataforma (un UUID y
el identificador de la evaluación). Nunca se usa un nombre que escriba el usuario, así que no hay
rutas que escapen de la carpeta. El archivo se escribe antes que la fila de la base de datos. Si
la transacción falla, el archivo se borra. Si la escritura falla, queda un registro
`report.failed`.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Final

from natxajo_auditor.auditing.results import AuditRun
from natxajo_auditor.auditing.store import MAX_LIST, AuditStore
from natxajo_auditor.core.contracts import (
    REPORT_EXPORT_PERMISSION,
    REPORT_READ_PERMISSION,
    OperationGate,
)
from natxajo_auditor.core.events import COMPANY_ID
from natxajo_auditor.core.exceptions import NatxajoError, ValidationError
from natxajo_auditor.core.utilities import (
    Clock,
    atomic_write_bytes,
    sha256_bytes,
    sha256_file,
    to_iso,
)
from natxajo_auditor.reporting.formats import FORMATS, ReportMeta, render
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database

EVENT_EXPORTED: Final = "report.exported"
EVENT_FAILED: Final = "report.failed"
FILE_PREFIX: Final = "informe-"


class ReportService:
    def __init__(
        self,
        *,
        database: Database,
        audit: AuditLog,
        gate: OperationGate,
        clock: Clock,
        reports_dir: Path,
        platform_version: str,
    ) -> None:
        self._database = database
        self._audit = audit
        self._gate = gate
        self._clock = clock
        self._reports_dir = reports_dir
        self._platform_version = platform_version
        self._evaluations = AuditStore(database)

    def export(self, token: str, company_id: str, run_id: str, fmt: str) -> dict[str, object]:
        """Escribe un informe de una evaluación de la empresa y lo registra."""
        _check_company(company_id)
        _check_format(fmt)

        def operation() -> dict[str, object]:
            username = self._gate.username_for(token)
            run = self._evaluations.load(company_id, run_id)
            return self._write(run, company_id, fmt, username)

        return self._gate.run(token, REPORT_EXPORT_PERMISSION, operation, company_id=company_id)

    def history(
        self, token: str, company_id: str | None, *, limit: int = 50
    ) -> list[dict[str, object]]:
        if company_id is not None:
            _check_company(company_id)
        if not 1 <= limit <= MAX_LIST:
            raise ValidationError(f"el número de informes debe estar entre 1 y {MAX_LIST}")

        def operation() -> list[dict[str, object]]:
            where = "" if company_id is None else "WHERE company_id = ?"
            params: tuple[object, ...] = () if company_id is None else (company_id,)
            rows = self._database.fetchall(
                "SELECT id, run_id, company_id, format, username, relative_path, sha256, "
                f"size_bytes, created_at FROM report_exports {where} "
                "ORDER BY created_at DESC, id DESC LIMIT ?",
                (*params, limit),
            )
            return [
                {
                    "id": row[0],
                    "evaluacion": row[1],
                    "empresa": row[2],
                    "formato": row[3],
                    "usuario": row[4],
                    "ruta": row[5],
                    "sha256": row[6],
                    "bytes": row[7],
                    "creado": row[8],
                }
                for row in rows
            ]

        return self._gate.run(token, REPORT_READ_PERMISSION, operation, company_id=company_id)

    def verify(self, token: str, company_id: str) -> list[dict[str, object]]:
        """Compara cada informe registrado con su archivo y busca archivos sin registro."""
        _check_company(company_id)

        def operation() -> list[dict[str, object]]:
            return self._verify(company_id)

        return self._gate.run(token, REPORT_READ_PERMISSION, operation, company_id=company_id)

    def _write(self, run: AuditRun, company_id: str, fmt: str, username: str) -> dict[str, object]:
        report_id = str(uuid.uuid4())
        meta = ReportMeta(
            report_id=report_id,
            generated_at=to_iso(self._clock()),
            platform_version=self._platform_version,
            username=username,
        )
        content = render(run, meta, fmt)
        digest = sha256_bytes(content)
        name = f"{FILE_PREFIX}{run.run_id}-{report_id}.{fmt}"
        relative = f"{company_id}/{name}"
        target = self._reports_dir / company_id / name
        try:
            atomic_write_bytes(target, content)
            with self._database.transaction() as connection:
                connection.execute(
                    "INSERT INTO report_exports (id, run_id, company_id, format, username, "
                    "relative_path, sha256, size_bytes, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        report_id,
                        run.run_id,
                        company_id,
                        fmt,
                        username,
                        relative,
                        digest,
                        len(content),
                        meta.generated_at,
                    ),
                )
                self._audit.record(
                    EVENT_EXPORTED,
                    {"run_id": run.run_id, "report_id": report_id, "format": fmt},
                    connection,
                    company_id=company_id,
                    actor=username,
                )
        except BaseException as exc:
            # El identificador es nuevo: el archivo que se borra es el que acabamos de escribir.
            target.unlink(missing_ok=True)
            self._audit.record(
                EVENT_FAILED,
                {"run_id": run.run_id, "format": fmt, "reason": _reason(exc)},
                company_id=company_id,
                actor=username,
            )
            raise
        return {
            "id": report_id,
            "evaluacion": run.run_id,
            "empresa": company_id,
            "formato": fmt,
            "ruta": relative,
            "sha256": digest,
            "bytes": len(content),
            "creado": meta.generated_at,
        }

    def _verify(self, company_id: str) -> list[dict[str, object]]:
        rows = self._database.fetchall(
            "SELECT id, relative_path, sha256, size_bytes FROM report_exports "
            "WHERE company_id = ? ORDER BY created_at, id",
            (company_id,),
        )
        findings: list[dict[str, object]] = []
        registered: set[str] = set()
        for report_id, relative, digest, size in rows:
            registered.add(str(relative))
            findings.append(
                {
                    "id": report_id,
                    "ruta": relative,
                    "estado": self._file_state(str(relative), str(digest), int(size)),
                }
            )
        company_dir = self._reports_dir / company_id
        if company_dir.is_dir():
            for path in sorted(company_dir.glob(f"{FILE_PREFIX}*")):
                relative = f"{company_id}/{path.name}"
                if relative not in registered and path.is_file():
                    findings.append({"id": "", "ruta": relative, "estado": "huerfano"})
        return findings

    def _file_state(self, relative: str, digest: str, size: int) -> str:
        path = (self._reports_dir / relative).resolve()
        root = self._reports_dir.resolve()
        if root not in path.parents:
            return "fuera_de_carpeta"
        if not path.is_file():
            return "faltante"
        if path.stat().st_size != size or sha256_file(path) != digest:
            return "alterado"
        return "correcto"


def _check_company(company_id: str) -> None:
    if not isinstance(company_id, str) or COMPANY_ID.fullmatch(company_id) is None:
        raise ValidationError("el identificador de empresa no es válido")


def _check_format(fmt: str) -> None:
    if fmt not in FORMATS:
        raise ValidationError(f"formato no soportado; use uno de [{', '.join(FORMATS)}]")


def _reason(exc: BaseException) -> str:
    if isinstance(exc, NatxajoError):
        return str(exc)[:200]
    return "error de escritura del informe"
