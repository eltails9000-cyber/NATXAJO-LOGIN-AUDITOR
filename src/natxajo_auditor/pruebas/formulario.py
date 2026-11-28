"""Construcción de los campos de cada solicitud y lectura de los formularios HTML de la aplicación.

`construir_campos` aplica la regla de los casos: un valor `None` omite el campo y una cadena vacía lo
envía vacío. Así las pruebas de «campo omitido» y «campo vacío» son distintas de verdad.
"""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Final

from natxajo_auditor.pruebas.modelo import CONTRASENA, IDENTIDAD, Formulario

_ETIQUETAS_DE_CAMPO: Final = frozenset({"input", "select", "textarea", "button"})


class _LectorDeFormulario(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ocultos: dict[str, str] = {}
        self.nombres: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in _ETIQUETAS_DE_CAMPO:
            return
        datos = {clave: valor or "" for clave, valor in attrs}
        nombre = datos.get("name", "")
        if not nombre:
            return
        self.nombres.add(nombre)
        if tag == "input" and datos.get("type", "").lower() == "hidden":
            self.ocultos[nombre] = datos.get("value", "")


def campos_ocultos(html: str) -> dict[str, str]:
    """Campos ocultos de una página (por ejemplo, el token CSRF) con su valor."""
    lector = _LectorDeFormulario()
    lector.feed(html)
    lector.close()
    return dict(lector.ocultos)


def nombres_de_campos(html: str) -> frozenset[str]:
    """Nombres de todos los campos de formulario de una página."""
    lector = _LectorDeFormulario()
    lector.feed(html)
    lector.close()
    return frozenset(lector.nombres)


def construir_campos(
    formulario: Formulario,
    *,
    identidad: str | None,
    contrasena: str | None,
    token: str | None = None,
    codigo_mfa: str | None = None,
) -> dict[str, str]:
    """Campos de una petición. `None` omite el campo; `""` lo envía vacío."""
    campos = dict(formulario.extra)
    if identidad is not None:
        campos[formulario.campos[IDENTIDAD]] = identidad
    if contrasena is not None:
        campos[formulario.campos[CONTRASENA]] = contrasena
    if token is not None and formulario.csrf is not None:
        campos[formulario.csrf.campo] = token
    if codigo_mfa is not None and formulario.mfa is not None:
        campos[formulario.mfa.campo] = codigo_mfa
    return campos
