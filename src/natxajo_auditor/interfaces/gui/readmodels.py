"""Modelos de lectura: convierten lo que devuelven los servicios en datos para las pantallas.

Reglas:
- Cada consulta pasa por el guardián o por el servicio que ya lo usa. La interfaz no lee la base
  de datos ni los archivos directamente.
- Las pantallas de plataforma (plugins, módulos, mantenimiento) no se consultan para cuentas de
  empresa: se responde «solo plataforma» sin llamar al servicio, para no llenar la auditoría de
  denegaciones por simple navegación.
- La gravedad de un evento es una clasificación fija para mostrarla: no es un motor de detección.
"""

from __future__ import annotations

import platform
import sqlite3
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from natxajo_auditor.core.contracts import (
    ACCOUNT_READ_PERMISSION,
    COMPANY_READ_PERMISSION,
    EVENT_READ_PERMISSION,
    MODULE_READ_PERMISSION,
    PLATFORM_COMPANY,
    SCOPE_DENIED,
    SESSION_READ_PERMISSION,
)
from natxajo_auditor.core.events import CATALOG
from natxajo_auditor.core.exceptions import AuthorizationError, SessionError
from natxajo_auditor.core.utilities import to_iso, utc_now
from natxajo_auditor.interfaces.gui.http_security import GuiError
from natxajo_auditor.kernel.kernel import Kernel

T = TypeVar("T")
MAX_SCAN = 1000
EVALUATION_LIMIT = 100
REPORT_LIMIT = 100
ALERT_LIST_LIMIT = 20
PLATFORM_ONLY_MESSAGE = "Disponible solo para la cuenta de la plataforma."
HIGH_SEVERITY_EVENTS = frozenset(
    {
        "operation.denied",
        "plugin.rejected",
        "plugin.quarantined",
        "plugin.publisher_revoked",
        "account.login_blocked",
        "installation.code_rejected",
        "report.failed",
    }
)


@dataclass(frozen=True)
class Viewer:
    username: str
    company_id: str
    platform: bool


def severity_of(event_type: str, category: str) -> str:
    """alta: denegaciones, rechazos, cuarentenas, bloqueos y fallos. media: resto de seguridad.
    baja: operativo."""
    if event_type in HIGH_SEVERITY_EVENTS:
        return "alta"
    if category == "seguridad":
        return "media"
    return "baja"


def _section(data: object, reason: str | None) -> dict[str, object]:
    return {
        "disponible": reason is None,
        "datos": data if reason is None else None,
        "motivo": reason,
    }


def _guarded(read: Callable[[], T]) -> tuple[T | None, str | None]:
    """Ejecuta una lectura de una sección. Un permiso denegado solo afecta a esa sección. La
    caducidad de la sesión no se captura: debe llegar a la capa de la aplicación."""
    try:
        return read(), None
    except SessionError:
        raise
    except GuiError as exc:
        return None, exc.message
    except AuthorizationError as exc:
        return None, str(exc)


def _require_platform(viewer: Viewer) -> None:
    if not viewer.platform:
        raise GuiError(403, "solo_plataforma", PLATFORM_ONLY_MESSAGE)


def _event_view(row: dict[str, Any]) -> dict[str, object]:
    event_type = str(row["event_type"])
    category = str(row["category"])
    return {
        "id": row["id"],
        "tipo": event_type,
        "categoria": category,
        "gravedad": severity_of(event_type, category),
        "creado": row["created_at"],
        "empresa": row["company_id"],
        "actor": row["actor"],
        "carga": row["payload"],
    }


def _account_view(account: Any) -> dict[str, object]:
    return {
        "usuario": account.username,
        "estado": account.status,
        "roles": list(account.roles),
        "empresa": account.company_id,
    }


def _plugin_view(record: Any) -> dict[str, object]:
    return {
        "id": record.plugin_id,
        "version": record.version,
        "habilitado": record.enabled,
        "cuarentena": record.quarantined,
        "editor": record.publisher_key_id,
        "confianza": record.trust_level,
        "integridad": record.integrity_sha256,
        "dependencias": list(record.dependencies),
        "revision_aprobada": record.approved_review,
        "version_anterior": record.previous_version,
    }


def _module_view(status: Any) -> dict[str, object]:
    manifest = status.manifest
    return {
        "id": manifest.module_id,
        "nombre": manifest.name,
        "version": manifest.version,
        "descripcion": manifest.description,
        "requiere": list(manifest.requires),
        "permisos": list(manifest.permissions),
        "habilitado": status.enabled,
        "problemas": list(status.problems),
    }


def _plugin_summary(plugins: list[dict[str, object]]) -> dict[str, object]:
    return {
        "total": len(plugins),
        "habilitados": sum(1 for p in plugins if p["habilitado"]),
        "cuarentena": sum(1 for p in plugins if p["cuarentena"]),
    }


def _module_summary(modules: list[dict[str, object]]) -> dict[str, object]:
    return {
        "total": len(modules),
        "habilitados": sum(1 for m in modules if m["habilitado"]),
        "con_problemas": sum(1 for m in modules if m["problemas"]),
    }


class ReadModels:
    def __init__(self, kernel: Kernel) -> None:
        self._kernel = kernel

    def viewer(self, token: str) -> Viewer:
        actor = self._kernel.security.guard.actor_for(token)
        return Viewer(actor.username, actor.company_id, actor.is_platform)

    def scope(self, viewer: Viewer, requested: str | None) -> str | None:
        """Empresa sobre la que se consulta. Una cuenta de empresa solo ve la suya."""
        if viewer.platform:
            return requested or None
        if requested and requested != viewer.company_id:
            raise GuiError(403, "ambito", SCOPE_DENIED)
        return viewer.company_id

    def dashboard(self, token: str) -> dict[str, object]:
        viewer = self.viewer(token)
        scope = None if viewer.platform else viewer.company_id
        events, events_reason = _guarded(
            lambda: [_event_view(row) for row in self._scan(token, scope)]
        )
        items = events or []
        state, state_reason = _guarded(lambda: self._platform_diagnostic(token, viewer))
        plugins, plugins_reason = _guarded(lambda: self._plugin_views(token, viewer))
        modules, modules_reason = _guarded(lambda: self._module_views(token, viewer))
        sessions, sessions_reason = _guarded(lambda: self._session_views(token, scope))
        severity = Counter(str(item["gravedad"]) for item in items)
        types = Counter(str(item["tipo"]) for item in items).most_common(6)
        return {
            "usuario": viewer.username,
            "empresa": viewer.company_id,
            "plataforma": viewer.platform,
            "estado": _section(state, state_reason),
            "plugins": _section(
                None if plugins is None else _plugin_summary(plugins), plugins_reason
            ),
            "modulos": _section(
                None if modules is None else _module_summary(modules), modules_reason
            ),
            "sesiones": _section(
                None if sessions is None else {"activas": len(sessions), "lista": sessions[:5]},
                sessions_reason,
            ),
            "alertas": _section(
                [item for item in items if item["gravedad"] == "alta"][:5], events_reason
            ),
            "actividad": _section(items[:10], events_reason),
            "gravedad": _section(dict(severity), events_reason),
            "tipos": _section(
                [{"tipo": name, "ocurrencias": count} for name, count in types],
                events_reason,
            ),
            "analizados": len(items),
        }

    def events(
        self,
        token: str,
        *,
        category: str | None,
        severity: str | None,
        event_type: str | None,
        company: str | None,
        limit: int,
    ) -> dict[str, object]:
        viewer = self.viewer(token)
        scope = self.scope(viewer, company)
        rows = self._scan(token, scope, category)
        views = [_event_view(row) for row in rows]
        if severity:
            views = [view for view in views if view["gravedad"] == severity]
        if event_type:
            needle = event_type.lower()
            views = [view for view in views if needle in str(view["tipo"]).lower()]
        return {
            "eventos": views[:limit],
            "coincidencias": len(views),
            "analizados": len(rows),
            "limite_analisis": MAX_SCAN,
            "empresa": scope,
        }

    def evaluations(self, token: str, company: str | None) -> dict[str, object]:
        scope = self.scope(self.viewer(token), company)
        records = self._kernel.auditing.history(token, scope, limit=EVALUATION_LIMIT)
        return {"evaluaciones": records, "empresa": scope}

    def evaluation(self, token: str, company: str | None, run_id: str) -> dict[str, object]:
        scope = self.scope(self.viewer(token), company)
        if scope is None:
            raise GuiError(422, "validacion", "Indique la empresa de la evaluación")
        return {"evaluacion": self._kernel.auditing.get_run(token, scope, run_id)}

    def reports(self, token: str, company: str | None) -> dict[str, object]:
        scope = self.scope(self.viewer(token), company)
        records = self._kernel.reports.history(token, scope, limit=REPORT_LIMIT)
        return {"informes": records, "empresa": scope}

    def accounts(self, token: str, company: str | None) -> dict[str, object]:
        scope = self.scope(self.viewer(token), company)
        security = self._kernel.security
        rows = security.guard.run(
            token,
            ACCOUNT_READ_PERMISSION,
            lambda: security.accounts.accounts(company_id=scope),
            company_id=scope,
        )
        return {"cuentas": [_account_view(account) for account in rows], "empresa": scope}

    def account_detail(self, token: str, username: str) -> dict[str, object]:
        viewer = self.viewer(token)
        security = self._kernel.security
        scope = None if viewer.platform else viewer.company_id

        def operation() -> dict[str, object]:
            account = security.accounts.find(username)
            if account is None or (not viewer.platform and account.company_id != scope):
                # Mismo mensaje exista o no la cuenta: no se revela qué usuarios hay en otras empresas.
                raise GuiError(404, "no_encontrada", "La cuenta no existe o no es visible")
            permissions = sorted(str(p) for p in security.authorizer.effective(account.username))
            live = security.sessions.list_live(security.accounts, company_id=account.company_id)
            return {
                "cuenta": _account_view(account),
                "permisos": permissions,
                "sesiones_activas": sum(1 for s in live if s.username == account.username),
            }

        return security.guard.run(token, ACCOUNT_READ_PERMISSION, operation, company_id=scope)

    def companies(self, token: str) -> dict[str, object]:
        viewer = self.viewer(token)
        security = self._kernel.security
        if viewer.platform:
            rows = security.guard.run(
                token,
                COMPANY_READ_PERMISSION,
                lambda: security.companies.list_companies(),
                company_id=None,
            )
        else:
            rows = security.guard.run(
                token,
                COMPANY_READ_PERMISSION,
                lambda: [security.companies.get(viewer.company_id)],
                company_id=viewer.company_id,
            )
        return {
            "empresas": [
                {"id": company.company_id, "nombre": company.name, "creada": company.created_at}
                for company in rows
            ]
        }

    def sessions(self, token: str, company: str | None) -> dict[str, object]:
        scope = self.scope(self.viewer(token), company)
        return {"sesiones": self._session_views(token, scope), "empresa": scope}

    def plugins(self, token: str) -> dict[str, object]:
        viewer = self.viewer(token)
        _require_platform(viewer)
        views = self._plugin_views(token, viewer)
        return {"plugins": views, "resumen": _plugin_summary(views)}

    def modules(self, token: str) -> dict[str, object]:
        viewer = self.viewer(token)
        _require_platform(viewer)
        views = self._module_views(token, viewer)
        return {"modulos": views, "resumen": _module_summary(views)}

    def catalog(self, token: str, company: str | None) -> dict[str, object]:
        scope = self.scope(self.viewer(token), company)
        rows = self._scan(token, scope)
        counts = Counter(str(row["event_type"]) for row in rows)
        entries = [
            {
                "tipo": name,
                "categoria": spec.category.value,
                "obligatorias": sorted(spec.required),
                "opcionales": sorted(spec.optional),
                "ocurrencias": counts.get(name, 0),
            }
            for name, spec in sorted(CATALOG.items())
        ]
        return {"tipos": entries, "analizados": len(rows), "limite_analisis": MAX_SCAN}

    def security_overview(self, token: str, company: str | None) -> dict[str, object]:
        viewer = self.viewer(token)
        scope = self.scope(viewer, company)
        security = self._kernel.security
        alerts = [
            view
            for view in (_event_view(row) for row in self._scan(token, scope))
            if view["gravedad"] == "alta"
        ][:ALERT_LIST_LIMIT]
        accounts, accounts_reason = _guarded(
            lambda: security.guard.run(
                token,
                ACCOUNT_READ_PERMISSION,
                lambda: security.accounts.accounts(company_id=scope),
                company_id=scope,
            )
        )
        sessions, sessions_reason = _guarded(lambda: self._session_views(token, scope))
        plugins, plugins_reason = _guarded(lambda: self._plugin_views(token, viewer))
        modules, modules_reason = _guarded(lambda: self._module_views(token, viewer))
        disabled = (
            None
            if accounts is None
            else [_account_view(a) for a in accounts if a.status == "disabled"]
        )
        return {
            "instalacion_pendiente": security.installer.is_pending(),
            "alertas": alerts,
            "cuentas": _section(
                None if accounts is None else {"total": len(accounts), "deshabilitadas": disabled},
                accounts_reason,
            ),
            "sesiones": _section(
                None if sessions is None else {"activas": len(sessions)}, sessions_reason
            ),
            "plugins_en_cuarentena": _section(
                None if plugins is None else [p for p in plugins if p["cuarentena"]],
                plugins_reason,
            ),
            "modulos_con_problemas": _section(
                None if modules is None else [m for m in modules if m["problemas"]],
                modules_reason,
            ),
            "empresa": scope,
        }

    def maintenance(self, token: str) -> dict[str, object]:
        _require_platform(self.viewer(token))
        return self._kernel.maintenance.diagnose(token)

    def cleanup_plan(self, token: str, hours: int) -> dict[str, object]:
        _require_platform(self.viewer(token))
        paths = self._kernel.maintenance.plan_cleanup(token, older_than_hours=hours)
        return {"horas": hours, "archivos": paths}

    def diagnostic_export(self, token: str) -> dict[str, object]:
        _require_platform(self.viewer(token))
        report = dict(self._kernel.maintenance.diagnose(token))
        report["generado"] = to_iso(utc_now())
        report["version"] = self._kernel.kernel_version
        return report

    def system_info(self, token: str) -> dict[str, object]:
        """Versión para cualquier cuenta. El detalle técnico (estado, servicios, versiones de Python
        y SQLite, sistema operativo) solo para la plataforma: una empresa no lo ve."""
        version = self._kernel.kernel_version
        if not self.viewer(token).platform:
            return {"version": version, "restringido": True}
        health = self._kernel.health()
        services = health["services"]
        return {
            "version": version,
            "restringido": False,
            "estado_nucleo": health["state"],
            "servicios": len(services) if isinstance(services, list) else 0,
            "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version,
            "sistema": platform.system(),
        }

    def _scan(self, token: str, scope: str | None, category: str | None = None) -> list[Any]:
        audit = self._kernel.audit
        return self._kernel.security.guard.run(
            token,
            EVENT_READ_PERMISSION,
            lambda: audit.list_events(MAX_SCAN, company_id=scope, category=category),
            company_id=scope,
        )

    def _session_views(self, token: str, scope: str | None) -> list[dict[str, object]]:
        security = self._kernel.security
        rows = security.guard.run(
            token,
            SESSION_READ_PERMISSION,
            lambda: security.sessions.list_live(security.accounts, company_id=scope),
            company_id=scope,
        )
        return [
            {
                "usuario": item.username,
                "empresa": item.company_id,
                "creada": item.created_at,
                "ultima_actividad": item.last_activity,
                "expira": item.expires_at,
                "reautenticada": item.reauthenticated,
            }
            for item in rows
        ]

    def _plugin_views(self, token: str, viewer: Viewer) -> list[dict[str, object]]:
        _require_platform(viewer)
        return [_plugin_view(record) for record in self._kernel.plugins.status(token)]

    def _module_views(self, token: str, viewer: Viewer) -> list[dict[str, object]]:
        _require_platform(viewer)
        modules = self._kernel.modules
        statuses = self._kernel.security.guard.run(
            token,
            MODULE_READ_PERMISSION,
            lambda: modules.list_modules(),
            company_id=PLATFORM_COMPANY,
        )
        return [_module_view(status) for status in statuses]

    def _platform_diagnostic(self, token: str, viewer: Viewer) -> dict[str, object]:
        _require_platform(viewer)
        return self._kernel.maintenance.diagnose(token)
