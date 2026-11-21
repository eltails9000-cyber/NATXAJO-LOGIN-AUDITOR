"""Ámbito de empresa: quién actúa y sobre qué empresa puede actuar.

Reglas:
- La empresa de un actor sale de su cuenta en la base de datos, no de ninguna entrada del usuario.
- Una cuenta de una empresa solo actúa sobre su empresa.
- Una cuenta de la empresa `plataforma` puede actuar sobre cualquier empresa. Las operaciones
  de la instalación (versiones, módulos, plugins, copias, empresas) exigen esa empresa.
- Ningún permiso concede acceso a otra empresa: el permiso se comprueba además del ámbito.
"""

from __future__ import annotations

from dataclasses import dataclass

PLATFORM_COMPANY = "plataforma"
SCOPE_DENIED = "la operación pertenece a otra empresa"


@dataclass(frozen=True)
class Actor:
    """Quien realiza una operación, con la empresa que consta en su cuenta."""

    username: str
    company_id: str
    session_id: int

    @property
    def is_platform(self) -> bool:
        return self.company_id == PLATFORM_COMPANY


def company_allows(actor_company: str, company_id: str) -> bool:
    """True si una cuenta de la empresa `actor_company` puede actuar sobre `company_id`."""
    return actor_company == PLATFORM_COMPANY or actor_company == company_id


def may_act_on(actor: Actor, company_id: str) -> bool:
    """True si el actor puede actuar sobre la empresa indicada."""
    return company_allows(actor.company_id, company_id)
