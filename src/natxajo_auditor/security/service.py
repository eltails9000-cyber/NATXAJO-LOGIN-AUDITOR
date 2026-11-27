"""Servicio de seguridad: agrupa empresas, cuentas, roles, permisos temporales, sesiones,
instalación y el guardián.

Es el único punto que usan el kernel y la terminal. Las piezas internas no se exponen a la
interfaz directamente, salvo lo que la terminal necesita para presentar el menú.

`create_account` y `set_roles` son vías internas de confianza: no comprueban quién las pide. La
terminal crea cuentas solo después de que el guardián haya validado la operación y su ámbito. Para
cambiar roles desde fuera del proceso, usar `change_roles`, que sí pasa por el guardián.
"""

from __future__ import annotations

from collections.abc import Iterable

from natxajo_auditor.core.contracts import ACCOUNT_ADMIN_PERMISSION, PLATFORM_COMPANY
from natxajo_auditor.core.utilities import Clock
from natxajo_auditor.security.accounts import DISABLED, Account, AccountStore
from natxajo_auditor.security.authorization import Authorizer
from natxajo_auditor.security.companies import CompanyStore
from natxajo_auditor.security.grants import GrantStore
from natxajo_auditor.security.guard import OperationGuard
from natxajo_auditor.security.installer import Installer
from natxajo_auditor.security.roles import RoleStore
from natxajo_auditor.security.sessions import SessionStore
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database


class SecurityService:
    def __init__(
        self,
        database: Database,
        audit: AuditLog,
        clock: Clock,
        password_iterations: int,
    ) -> None:
        self.roles = RoleStore(database)
        self.accounts = AccountStore(database, audit, clock, password_iterations)
        self.companies = CompanyStore(database, audit)
        self.grants = GrantStore(database, audit, clock)
        self.sessions = SessionStore(database, audit, clock)
        self.authorizer = Authorizer(database, self.roles, self.grants)
        self.guard = OperationGuard(self.sessions, self.authorizer, audit, self.accounts)
        self.installer = Installer(database, audit, clock, password_iterations, self.accounts)
        self.roles.ensure_builtins()

    def has_accounts(self) -> bool:
        return self.accounts.count() > 0

    def create_account(
        self,
        username: str,
        password: str,
        roles: Iterable[str],
        company_id: str = PLATFORM_COMPANY,
    ) -> Account:
        """Alta de cuenta en una empresa. Solo tras completar la instalación inicial."""
        return self.accounts.create(username, password, roles, company_id)

    def change_roles(
        self,
        token: str,
        username: str,
        roles: Iterable[str],
        *,
        confirmed: bool,
    ) -> None:
        """Sustituye los roles de una cuenta a través del guardián.

        Es de plataforma: una cuenta de empresa no concede roles, ni siquiera dentro de su empresa.
        Es crítica: exige confirmación y reautenticación reciente. Asignar `administrador` queda
        limitado a la plataforma por ese mismo control.
        """
        role_names = tuple(roles)

        def operation() -> None:
            actor = self.guard.username_for(token)
            self.accounts.set_roles(username, role_names, actor=actor)

        self.guard.run(
            token,
            ACCOUNT_ADMIN_PERMISSION,
            operation,
            confirmed=confirmed,
            company_id=None,
        )

    def login(self, username: str, password: str) -> str:
        self.accounts.check_password(username, password)
        return self.sessions.open(username)

    def logout(self, token: str) -> None:
        self.sessions.close(token)

    def reauthenticate(self, token: str, password: str) -> None:
        self.sessions.reauthenticate(token, password, self.accounts)

    def disable_account(self, username: str) -> None:
        """Deshabilita una cuenta y cierra todas sus sesiones."""
        self.accounts.set_status(username, DISABLED)
        self.sessions.close_all(username)
