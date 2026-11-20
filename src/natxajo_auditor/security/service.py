"""Servicio de seguridad: agrupa cuentas, roles, permisos temporales, sesiones y el guardián.

Es el único punto que usan el kernel y la terminal. Las piezas internas no se exponen a la
interfaz directamente, salvo lo que la terminal necesita para presentar el menú.
"""

from __future__ import annotations

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.utilities import Clock
from natxajo_auditor.security.accounts import DISABLED, Account, AccountStore
from natxajo_auditor.security.authorization import Authorizer
from natxajo_auditor.security.grants import GrantStore
from natxajo_auditor.security.guard import OperationGuard
from natxajo_auditor.security.roles import ADMINISTRATOR, RoleStore
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
        self.grants = GrantStore(database, audit, clock)
        self.sessions = SessionStore(database, audit, clock)
        self.authorizer = Authorizer(database, self.roles, self.grants)
        self.guard = OperationGuard(self.sessions, self.authorizer, audit)
        self.roles.ensure_builtins()

    def has_accounts(self) -> bool:
        return self.accounts.count() > 0

    def bootstrap_administrator(self, username: str, password: str) -> Account:
        """Crea la primera cuenta, con el rol de administrador. Solo funciona sin cuentas."""
        if self.has_accounts():
            raise ValidationError(
                "ya existen cuentas; el administrador inicial solo se crea una vez"
            )
        return self.accounts.create(username, password, [ADMINISTRATOR])

    def create_account(self, username: str, password: str, roles: list[str]) -> Account:
        return self.accounts.create(username, password, roles)

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
