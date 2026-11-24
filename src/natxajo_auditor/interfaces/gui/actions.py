"""Acciones de la interfaz: solo llaman a operaciones que ya existen y que ya están protegidas.

Ninguna acción decide por sí misma si el usuario puede hacerla. Los servicios aplican el guardián,
el ámbito de empresa, la confirmación y la reautenticación. Lo que la interfaz añade es la
confirmación visual, que se envía como `confirmed`; el servicio la exige igualmente.

No se exponen habilitar ni deshabilitar plugins: esas operaciones no pasan por el guardián en el
gestor de plugins y se quedan en la API interna hasta la etapa de terminal de plugins.
"""

from __future__ import annotations

from pathlib import Path

from natxajo_auditor.core.contracts import MODULE_EXECUTE_PERMISSION, PLATFORM_COMPANY
from natxajo_auditor.kernel.kernel import Kernel


class Actions:
    def __init__(self, kernel: Kernel) -> None:
        self._kernel = kernel

    def quarantine_plugin(self, token: str, plugin_id: str, reason: str) -> dict[str, object]:
        disabled = self._kernel.plugins.quarantine(token, plugin_id, reason)
        return {"plugin": plugin_id, "deshabilitados": list(disabled)}

    def release_plugin(self, token: str, plugin_id: str, *, confirmed: bool) -> dict[str, object]:
        self._kernel.plugins.release_quarantine(token, plugin_id, confirmed=confirmed)
        return {"plugin": plugin_id, "liberado": True}

    def update_plugin(self, token: str, folder: Path, *, confirmed: bool) -> dict[str, object]:
        record = self._kernel.plugins.update_package(token, folder, confirmed=confirmed)
        return {"plugin": record.plugin_id, "version": record.version, "habilitado": record.enabled}

    def rollback_plugin(self, token: str, plugin_id: str, *, confirmed: bool) -> dict[str, object]:
        record = self._kernel.plugins.rollback(token, plugin_id, confirmed=confirmed)
        return {"plugin": record.plugin_id, "version": record.version, "habilitado": record.enabled}

    def enable_module(self, token: str, module_id: str, *, confirmed: bool) -> dict[str, object]:
        modules = self._kernel.modules
        changed = self._kernel.security.guard.run(
            token,
            MODULE_EXECUTE_PERMISSION,
            lambda: modules.enable(module_id),
            confirmed=confirmed,
            company_id=PLATFORM_COMPANY,
        )
        return {"modulo": module_id, "habilitados": list(changed)}

    def disable_module(self, token: str, module_id: str, *, confirmed: bool) -> dict[str, object]:
        modules = self._kernel.modules
        self._kernel.security.guard.run(
            token,
            MODULE_EXECUTE_PERMISSION,
            lambda: modules.disable(module_id),
            confirmed=confirmed,
            company_id=PLATFORM_COMPANY,
        )
        return {"modulo": module_id, "deshabilitado": True}

    def export_report(
        self, token: str, company_id: str, run_id: str, fmt: str
    ) -> dict[str, object]:
        return {"informe": self._kernel.reports.export(token, company_id, run_id, fmt)}

    def verify_reports(self, token: str, company_id: str) -> dict[str, object]:
        return {"verificacion": self._kernel.reports.verify(token, company_id)}

    def apply_cleanup(self, token: str, hours: int, *, confirmed: bool) -> dict[str, object]:
        return self._kernel.maintenance.apply_cleanup(
            token, older_than_hours=hours, confirmed=confirmed
        )
