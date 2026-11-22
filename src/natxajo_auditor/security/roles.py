"""Roles y permisos: roles integrados, roles propios con herencia, separación de funciones y
anti-escalada.

- Un rol concede permisos directamente y por herencia de sus padres.
- La herencia es acíclica por construcción: un rol nuevo solo puede heredar de roles existentes.
  Su profundidad está limitada a MAX_INHERITANCE_DEPTH niveles.
- Un rol propio solo puede conceder permisos que quien lo crea ya posee. Así nadie puede darse
  más de lo que tiene, ni siquiera por herencia.
- Dos roles en SEPARATED_ROLES no pueden asignarse a la misma cuenta.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.core.permissions import Permission, covers, parse_permission
from natxajo_auditor.core.validation import require_identifier
from natxajo_auditor.storage.database import Database

MAX_INHERITANCE_DEPTH = 5
ADMINISTRATOR = "administrador"
OPERATOR = "operador"
AUDITOR = "auditor"

# nombre -> (permisos directos, roles padre)
BUILTIN_ROLES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    ADMINISTRATOR: (("*:*:*:*",), ()),
    OPERATOR: (
        ("*:*:*:leer", "versiones:nucleo:version:ejecutar", "modulos:nucleo:modulo:ejecutar"),
        (),
    ),
    AUDITOR: (("*:*:*:leer",), ()),
}
SEPARATED_ROLES: tuple[frozenset[str], ...] = (frozenset({OPERATOR, AUDITOR}),)


@dataclass(frozen=True)
class Role:
    name: str
    builtin: bool
    grants: tuple[str, ...]
    parents: tuple[str, ...]


def check_separation(role_names: Iterable[str]) -> None:
    present = set(role_names)
    for pair in SEPARATED_ROLES:
        if pair <= present:
            raise ValidationError(
                "separación de funciones: "
                + " y ".join(sorted(pair))
                + " no pueden asignarse a la misma cuenta"
            )


class RoleStore:
    def __init__(self, database: Database) -> None:
        self._database = database

    def ensure_builtins(self) -> None:
        """Crea los roles integrados si faltan. No modifica los que ya existen."""
        with self._database.transaction() as connection:
            for name, (grants, parents) in BUILTIN_ROLES.items():
                connection.execute(
                    "INSERT OR IGNORE INTO roles (name, builtin) VALUES (?, 1)", (name,)
                )
                for grant in grants:
                    connection.execute(
                        "INSERT OR IGNORE INTO role_grants (role_name, permission) VALUES (?, ?)",
                        (name, grant),
                    )
                for parent in parents:
                    connection.execute(
                        "INSERT OR IGNORE INTO role_parents (role_name, parent_name) VALUES (?, ?)",
                        (name, parent),
                    )

    def exists(self, name: str) -> bool:
        return bool(self._database.fetchall("SELECT 1 FROM roles WHERE name = ?", (name,)))

    def get(self, name: str) -> Role:
        rows = self._database.fetchall("SELECT name, builtin FROM roles WHERE name = ?", (name,))
        if not rows:
            raise ValidationError(f"rol no existe: {name}")
        grants = self._database.fetchall(
            "SELECT permission FROM role_grants WHERE role_name = ? ORDER BY permission", (name,)
        )
        parents = self._database.fetchall(
            "SELECT parent_name FROM role_parents WHERE role_name = ? ORDER BY parent_name",
            (name,),
        )
        return Role(
            name=str(rows[0][0]),
            builtin=bool(rows[0][1]),
            grants=tuple(str(row[0]) for row in grants),
            parents=tuple(str(row[0]) for row in parents),
        )

    def all_roles(self) -> list[Role]:
        names = self._database.fetchall("SELECT name FROM roles ORDER BY name")
        return [self.get(str(row[0])) for row in names]

    def effective_permissions(self, names: Iterable[str]) -> frozenset[Permission]:
        """Unión de los permisos de los roles indicados y de todos sus ancestros."""
        pending = list(names)
        visited: set[str] = set()
        result: set[Permission] = set()
        while pending:
            name = pending.pop()
            if name in visited:
                continue
            visited.add(name)
            role = self.get(name)
            for grant in role.grants:
                result.add(parse_permission(grant, allow_wildcards=True, source=f"rol {name}"))
            pending.extend(role.parents)
        return frozenset(result)

    def depth(self, name: str) -> int:
        """Número de niveles de la jerarquía, contando el propio rol."""
        role = self.get(name)
        if not role.parents:
            return 1
        return 1 + max(self.depth(parent) for parent in role.parents)

    def create_custom(
        self,
        name: str,
        grants: Iterable[str],
        parents: Iterable[str],
        actor: frozenset[Permission],
    ) -> Role:
        """Crea un rol propio. actor son los permisos de quien lo crea (anti-escalada)."""
        name = require_identifier(name, "nombre de rol", "rol")
        if self.exists(name):
            raise ValidationError(f"el rol ya existe: {name}")
        grant_list = list(grants)
        parent_list = list(parents)
        if len(set(grant_list)) != len(grant_list) or len(set(parent_list)) != len(parent_list):
            raise ValidationError("el rol tiene permisos o padres repetidos")
        if not grant_list and not parent_list:
            raise ValidationError("el rol debe conceder algún permiso o heredar de otro rol")
        parsed = [
            parse_permission(grant, allow_wildcards=True, source="rol") for grant in grant_list
        ]
        for parent in parent_list:
            if not self.exists(parent):
                raise ValidationError(f"rol padre no existe: {parent}")
        depth = 1 + max((self.depth(parent) for parent in parent_list), default=0)
        if depth > MAX_INHERITANCE_DEPTH:
            raise ValidationError(
                f"la herencia supera la profundidad máxima de {MAX_INHERITANCE_DEPTH} niveles"
            )
        required = set(parsed) | set(self.effective_permissions(parent_list))
        for permission in sorted(required, key=str):
            if not any(covers(held, permission) for held in actor):
                raise AuthorizationError(f"no puede conceder un permiso que no posee: {permission}")
        with self._database.transaction() as connection:
            connection.execute("INSERT INTO roles (name, builtin) VALUES (?, 0)", (name,))
            for grant in grant_list:
                connection.execute(
                    "INSERT INTO role_grants (role_name, permission) VALUES (?, ?)", (name, grant)
                )
            for parent in parent_list:
                connection.execute(
                    "INSERT INTO role_parents (role_name, parent_name) VALUES (?, ?)",
                    (name, parent),
                )
        return self.get(name)
