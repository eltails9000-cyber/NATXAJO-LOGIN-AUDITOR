"""Empresas: alta y consulta. Una empresa no se borra mientras tenga cuentas.

La empresa `plataforma` existe desde la migración 6 y no puede crearse ni borrarse. Las empresas
creadas aquí son de cliente.
"""

from __future__ import annotations

from dataclasses import dataclass

from natxajo_auditor.core.contracts import PLATFORM_COMPANY
from natxajo_auditor.core.events import COMPANY_ID
from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.validation import require_text
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database

MAX_NAME_LENGTH = 120


@dataclass(frozen=True)
class Company:
    company_id: str
    name: str
    created_at: str


class CompanyStore:
    def __init__(self, database: Database, audit: AuditLog) -> None:
        self._database = database
        self._audit = audit

    def exists(self, company_id: str) -> bool:
        return bool(self._database.fetchall("SELECT 1 FROM companies WHERE id = ?", (company_id,)))

    def get(self, company_id: str) -> Company:
        rows = self._database.fetchall(
            "SELECT id, name, created_at FROM companies WHERE id = ?", (company_id,)
        )
        if not rows:
            raise ValidationError(f"la empresa no existe: {company_id}")
        return _to_company(rows[0])

    def list_companies(self) -> list[Company]:
        rows = self._database.fetchall("SELECT id, name, created_at FROM companies ORDER BY id")
        return [_to_company(row) for row in rows]

    def create(self, company_id: str, name: str) -> Company:
        if not COMPANY_ID.fullmatch(company_id):
            raise ValidationError(
                f"identificador de empresa no válido: {company_id} (minúsculas, dígitos y "
                "guion; de 3 a 40 caracteres, empezando por letra)"
            )
        if company_id == PLATFORM_COMPANY or self.exists(company_id):
            raise ValidationError(f"la empresa ya existe: {company_id}")
        clean_name = require_text(name, "nombre", "empresa")
        if len(clean_name) > MAX_NAME_LENGTH:
            raise ValidationError(f"el nombre de la empresa supera {MAX_NAME_LENGTH} caracteres")
        with self._database.transaction() as connection:
            connection.execute(
                "INSERT INTO companies (id, name) VALUES (?, ?)", (company_id, clean_name)
            )
            self._audit.record(
                "company.created",
                {"empresa": company_id, "nombre": clean_name},
                connection=connection,
            )
        return self.get(company_id)


def _to_company(row: tuple[object, ...]) -> Company:
    return Company(company_id=str(row[0]), name=str(row[1]), created_at=str(row[2]))
