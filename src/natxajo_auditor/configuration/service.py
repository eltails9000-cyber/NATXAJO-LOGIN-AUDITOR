"""Restauración de configuración a través del guardián.

Es la única vía de restauración que exponen los servicios. Es una operación crítica de plataforma:
exige sesión, permiso, confirmación y reautenticación reciente. El guardián registra el resultado y
la restauración deja constancia en la auditoría con el archivo y el usuario.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from natxajo_auditor.configuration.manager import ConfigurationManager
from natxajo_auditor.core.contracts import (
    CONFIGURATION_RESTORE_PERMISSION,
    PLATFORM_COMPANY,
    OperationGate,
)
from natxajo_auditor.storage.audit import AuditLog

EVENT_RESTORED: Final = "configuration.restored"


class ConfigurationService:
    def __init__(
        self,
        *,
        manager: ConfigurationManager,
        gate: OperationGate,
        audit: AuditLog,
    ) -> None:
        self._manager = manager
        self._gate = gate
        self._audit = audit

    def restore(self, token: str, source: Path, *, confirmed: bool) -> None:
        """Restaura una copia verificada. Una copia que no verifica no cambia nada."""

        def operation() -> None:
            username = self._gate.username_for(token)
            self._manager.restore(source, authorized=True)
            self._audit.record(
                EVENT_RESTORED,
                {"archivo": source.name},
                company_id=PLATFORM_COMPANY,
                actor=username,
            )

        self._gate.run(
            token,
            CONFIGURATION_RESTORE_PERMISSION,
            operation,
            confirmed=confirmed,
            company_id=None,
        )
