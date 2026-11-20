"""Motor de autorización: permisos efectivos de una cuenta y comprobación de un permiso.

Los permisos efectivos son la unión de los permisos de sus roles (con herencia) y de sus permisos
temporales activos. Una cuenta deshabilitada no tiene ninguno.
"""

from __future__ import annotations

from natxajo_auditor.core.exceptions import AuthorizationError
from natxajo_auditor.security.accounts import ACTIVE
from natxajo_auditor.security.grants import GrantStore
from natxajo_auditor.security.permissions import Permission, covers, parse_permission
from natxajo_auditor.security.roles import RoleStore
from natxajo_auditor.storage.database import Database


class Authorizer:
    def __init__(self, database: Database, roles: RoleStore, grants: GrantStore) -> None:
        self._database = database
        self._roles = roles
        self._grants = grants

    def effective(self, username: str) -> frozenset[Permission]:
        rows = self._database.fetchall(
            "SELECT status FROM accounts WHERE username = ?", (username,)
        )
        if not rows or str(rows[0][0]) != ACTIVE:
            return frozenset()
        role_rows = self._database.fetchall(
            "SELECT role_name FROM account_roles WHERE username = ?", (username,)
        )
        from_roles = self._roles.effective_permissions(str(row[0]) for row in role_rows)
        return from_roles | frozenset(self._grants.active_permissions(username))

    def is_allowed(self, username: str, permission: str) -> bool:
        wanted = parse_permission(permission, source="permiso")
        return any(covers(held, wanted) for held in self.effective(username))

    def require(self, username: str, permission: str) -> None:
        if not self.is_allowed(username, permission):
            raise AuthorizationError(f"sin permiso: {permission}")
