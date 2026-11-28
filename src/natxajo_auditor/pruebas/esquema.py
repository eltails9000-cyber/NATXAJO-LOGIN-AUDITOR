"""Carga y validación de la configuración de pruebas: formularios, cuentas sintéticas y límites.

Cada archivo es JSON con `"version": 1`. Un error de validación indica la ruta del campo, nunca el
valor, para no reflejar datos sensibles en la salida. Los archivos no son obligatorios: sin ellos,
la lista correspondiente está vacía y los límites toman sus valores por defecto.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.pruebas.modelo import (
    CONTRASENA,
    CORREO_SINTETICO,
    IDENTIDAD,
    IDENTIFICADOR,
    LIMITES_MAXIMOS,
    LIMITES_MINIMOS,
    NOMBRE_CAMPO,
    RUTA,
    USUARIO_SINTETICO,
    VARIABLE_ENTORNO,
    Csrf,
    CuentaSintetica,
    Formulario,
    Limites,
    Mfa,
    ReglasRespuesta,
    TipoFormulario,
)

ARCHIVO_FORMULARIOS: Final = "formularios.json"
ARCHIVO_CUENTAS: Final = "cuentas.json"
ARCHIVO_LIMITES: Final = "limites.json"
VERSION_ESQUEMA: Final = 1
MAX_ARCHIVO_BYTES: Final = 262_144
MAX_MARCADORES: Final = 10
MAX_MARCADOR_LEN: Final = 120
MAX_LONGITUD_CAMPO: Final = 1024
MAX_VALOR_EXTRA: Final = 200
CLAVES_CUENTA: Final = frozenset({"id", "usuario", "variable_contrasena", "variable_mfa", "correo"})
CLAVES_FORMULARIO: Final = frozenset(
    {"id", "tipo", "ruta", "campos", "longitudes", "extra", "csrf", "mfa", "respuesta"}
)
CLAVES_LIMITES: Final = frozenset(
    {"max_solicitudes", "max_cuentas", "concurrencia", "pausa_ms", "timeout_s", "max_intentos"}
)


def leer_json(path: Path) -> Mapping[str, Any] | None:
    """Objeto JSON del archivo, o None si no existe. Rechaza archivos grandes y mal formados."""
    if not path.exists():
        return None
    try:
        if path.stat().st_size > MAX_ARCHIVO_BYTES:
            raise ValidationError(f"{path.name}: el archivo supera {MAX_ARCHIVO_BYTES} bytes")
        datos: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{path.name}: el archivo no es JSON válido") from exc
    if not isinstance(datos, dict) or datos.get("version") != VERSION_ESQUEMA:
        raise ValidationError(f'{path.name}: se espera un objeto con "version": {VERSION_ESQUEMA}')
    return datos


def cargar_formularios(directorio: Path) -> dict[str, Formulario]:
    datos = leer_json(directorio / ARCHIVO_FORMULARIOS)
    if datos is None:
        return {}
    _solo_claves(datos, frozenset({"version", "formularios"}), ARCHIVO_FORMULARIOS)
    lista = _lista(datos.get("formularios"), "formularios", 0, 50)
    resultado: dict[str, Formulario] = {}
    for indice, bruto in enumerate(lista):
        formulario = _formulario(bruto, f"formularios[{indice}]")
        if formulario.id in resultado:
            raise ValidationError(f"formularios: identificador repetido en '{formulario.id}'")
        resultado[formulario.id] = formulario
    return resultado


def cargar_cuentas(directorio: Path) -> dict[str, CuentaSintetica]:
    datos = leer_json(directorio / ARCHIVO_CUENTAS)
    if datos is None:
        return {}
    _solo_claves(datos, frozenset({"version", "cuentas"}), ARCHIVO_CUENTAS)
    lista = _lista(datos.get("cuentas"), "cuentas", 0, LIMITES_MAXIMOS.max_cuentas)
    cuentas: dict[str, CuentaSintetica] = {}
    usuarios: set[str] = set()
    for indice, bruto in enumerate(lista):
        cuenta = _cuenta(bruto, f"cuentas[{indice}]")
        if cuenta.id in cuentas or cuenta.usuario in usuarios:
            raise ValidationError(f"cuentas: identificador o usuario repetido en '{cuenta.id}'")
        cuentas[cuenta.id] = cuenta
        usuarios.add(cuenta.usuario)
    return cuentas


def cargar_limites(directorio: Path) -> Limites:
    datos = leer_json(directorio / ARCHIVO_LIMITES)
    if datos is None:
        return Limites()
    _solo_claves(datos, CLAVES_LIMITES | {"version"}, ARCHIVO_LIMITES)
    return Limites(
        max_solicitudes=_entero_en(
            datos,
            "max_solicitudes",
            LIMITES_MINIMOS.max_solicitudes,
            LIMITES_MAXIMOS.max_solicitudes,
            Limites().max_solicitudes,
        ),
        max_cuentas=_entero_en(
            datos,
            "max_cuentas",
            LIMITES_MINIMOS.max_cuentas,
            LIMITES_MAXIMOS.max_cuentas,
            Limites().max_cuentas,
        ),
        concurrencia=_entero_en(
            datos,
            "concurrencia",
            LIMITES_MINIMOS.concurrencia,
            LIMITES_MAXIMOS.concurrencia,
            Limites().concurrencia,
        ),
        pausa_ms=_entero_en(
            datos,
            "pausa_ms",
            LIMITES_MINIMOS.pausa_ms,
            LIMITES_MAXIMOS.pausa_ms,
            Limites().pausa_ms,
        ),
        timeout_s=_real_en(
            datos,
            "timeout_s",
            LIMITES_MINIMOS.timeout_s,
            LIMITES_MAXIMOS.timeout_s,
            Limites().timeout_s,
        ),
        max_intentos=_entero_en(
            datos,
            "max_intentos",
            LIMITES_MINIMOS.max_intentos,
            LIMITES_MAXIMOS.max_intentos,
            Limites().max_intentos,
        ),
    )


def _formulario(bruto: object, ruta: str) -> Formulario:
    objeto = _objeto(bruto, ruta)
    _solo_claves(objeto, CLAVES_FORMULARIO, ruta)
    tipo = _tipo(objeto.get("tipo"), f"{ruta}.tipo")
    campos_bruto = _objeto(objeto.get("campos"), f"{ruta}.campos")
    _solo_claves(campos_bruto, frozenset({IDENTIDAD, CONTRASENA}), f"{ruta}.campos")
    campos = {
        rol: _texto(campos_bruto.get(rol), f"{ruta}.campos.{rol}", NOMBRE_CAMPO)
        for rol in (IDENTIDAD, CONTRASENA)
    }
    if len(set(campos.values())) != len(campos):
        raise ValidationError(f"{ruta}.campos: identidad y contraseña usan el mismo nombre")

    longitudes: dict[str, tuple[int, int]] = {}
    longitudes_bruto = _objeto(objeto.get("longitudes", {}), f"{ruta}.longitudes")
    _solo_claves(longitudes_bruto, frozenset({IDENTIDAD, CONTRASENA}), f"{ruta}.longitudes")
    for rol, par in longitudes_bruto.items():
        if not isinstance(par, list) or len(par) != 2:
            raise ValidationError(f"{ruta}.longitudes.{rol}: se espera [mínimo, máximo]")
        minimo = _entero_valor(par[0], f"{ruta}.longitudes.{rol}", 0, MAX_LONGITUD_CAMPO)
        maximo = _entero_valor(par[1], f"{ruta}.longitudes.{rol}", 0, MAX_LONGITUD_CAMPO)
        if minimo > maximo:
            raise ValidationError(f"{ruta}.longitudes.{rol}: el mínimo supera al máximo")
        longitudes[str(rol)] = (minimo, maximo)

    extra_bruto = _objeto(objeto.get("extra", {}), f"{ruta}.extra")
    extra: dict[str, str] = {}
    for nombre, valor in extra_bruto.items():
        campo = _texto(nombre, f"{ruta}.extra", NOMBRE_CAMPO)
        if campo in campos.values():
            raise ValidationError(f"{ruta}.extra: '{campo}' sobrescribe identidad o contraseña")
        if not isinstance(valor, str) or len(valor) > MAX_VALOR_EXTRA:
            raise ValidationError(f"{ruta}.extra.{campo}: se espera un texto corto")
        extra[campo] = valor

    csrf = _csrf(objeto.get("csrf"), f"{ruta}.csrf")
    mfa = _mfa(objeto.get("mfa"), f"{ruta}.mfa")
    if (tipo is TipoFormulario.USUARIO_CONTRASENA_MFA) != (mfa is not None):
        raise ValidationError(f"{ruta}: el tipo usuario_contrasena_mfa exige el bloque mfa")

    return Formulario(
        id=_texto(objeto.get("id"), f"{ruta}.id", IDENTIFICADOR),
        tipo=tipo,
        ruta=_texto(objeto.get("ruta"), f"{ruta}.ruta", RUTA),
        campos=campos,
        longitudes=longitudes,
        extra=extra,
        reglas=_reglas(objeto.get("respuesta"), f"{ruta}.respuesta"),
        csrf=csrf,
        mfa=mfa,
    )


def _cuenta(bruto: object, ruta: str) -> CuentaSintetica:
    objeto = _objeto(bruto, ruta)
    _solo_claves(objeto, CLAVES_CUENTA, ruta)
    variable_mfa = objeto.get("variable_mfa")
    correo = objeto.get("correo")
    return CuentaSintetica(
        id=_texto(objeto.get("id"), f"{ruta}.id", IDENTIFICADOR),
        usuario=_texto(objeto.get("usuario"), f"{ruta}.usuario", USUARIO_SINTETICO),
        variable_contrasena=_texto(
            objeto.get("variable_contrasena"), f"{ruta}.variable_contrasena", VARIABLE_ENTORNO
        ),
        variable_mfa=(
            None
            if variable_mfa is None
            else _texto(variable_mfa, f"{ruta}.variable_mfa", VARIABLE_ENTORNO)
        ),
        correo=None if correo is None else _texto(correo, f"{ruta}.correo", CORREO_SINTETICO),
    )


def _reglas(bruto: object, ruta: str) -> ReglasRespuesta:
    objeto = _objeto(bruto, ruta)
    _solo_claves(objeto, frozenset({"exito", "fallo", "bloqueo", "ruta_login"}), ruta)
    return ReglasRespuesta(
        exito=_marcadores(objeto.get("exito"), f"{ruta}.exito", minimo=1),
        fallo=_marcadores(objeto.get("fallo"), f"{ruta}.fallo", minimo=1),
        bloqueo=_marcadores(objeto.get("bloqueo", []), f"{ruta}.bloqueo", minimo=0),
        ruta_login=_texto(objeto.get("ruta_login"), f"{ruta}.ruta_login", RUTA),
    )


def _csrf(bruto: object, ruta: str) -> Csrf | None:
    if bruto is None:
        return None
    objeto = _objeto(bruto, ruta)
    _solo_claves(objeto, frozenset({"campo", "pagina"}), ruta)
    return Csrf(
        campo=_texto(objeto.get("campo"), f"{ruta}.campo", NOMBRE_CAMPO),
        pagina=_texto(objeto.get("pagina"), f"{ruta}.pagina", RUTA),
    )


def _mfa(bruto: object, ruta: str) -> Mfa | None:
    if bruto is None:
        return None
    objeto = _objeto(bruto, ruta)
    _solo_claves(objeto, frozenset({"campo", "ruta", "marcador"}), ruta)
    marcadores = _marcadores([objeto.get("marcador")], f"{ruta}.marcador", minimo=1)
    return Mfa(
        campo=_texto(objeto.get("campo"), f"{ruta}.campo", NOMBRE_CAMPO),
        ruta=_texto(objeto.get("ruta"), f"{ruta}.ruta", RUTA),
        marcador=marcadores[0],
    )


def _tipo(valor: object, ruta: str) -> TipoFormulario:
    try:
        return TipoFormulario(str(valor))
    except ValueError as exc:
        opciones = ", ".join(sorted(t.value for t in TipoFormulario))
        raise ValidationError(f"{ruta}: tipo no válido; use uno de: {opciones}") from exc


def _marcadores(valor: object, ruta: str, *, minimo: int) -> tuple[str, ...]:
    lista = _lista(valor, ruta, minimo, MAX_MARCADORES)
    marcadores: list[str] = []
    for item in lista:
        if not isinstance(item, str) or not 1 <= len(item) <= MAX_MARCADOR_LEN:
            raise ValidationError(
                f"{ruta}: cada marcador debe tener entre 1 y {MAX_MARCADOR_LEN} caracteres"
            )
        marcadores.append(item)
    return tuple(marcadores)


def _lista(valor: object, ruta: str, minimo: int, maximo: int) -> list[Any]:
    if not isinstance(valor, list) or not minimo <= len(valor) <= maximo:
        raise ValidationError(f"{ruta}: se espera una lista de {minimo} a {maximo} elementos")
    return valor


def _objeto(valor: object, ruta: str) -> Mapping[str, Any]:
    if not isinstance(valor, dict):
        raise ValidationError(f"{ruta}: se espera un objeto")
    return valor


def _solo_claves(
    objeto: Mapping[str, Any], permitidas: frozenset[str] | Sequence[str], ruta: str
) -> None:
    desconocidas = sorted(set(objeto) - set(permitidas))
    if desconocidas:
        raise ValidationError(f"{ruta}: claves no admitidas: {', '.join(map(str, desconocidas))}")


def _texto(valor: object, ruta: str, patron: re.Pattern[str]) -> str:
    if not isinstance(valor, str) or patron.fullmatch(valor) is None:
        raise ValidationError(f"{ruta}: valor no válido")
    return valor


def _entero_valor(valor: object, ruta: str, minimo: int, maximo: int) -> int:
    if isinstance(valor, bool) or not isinstance(valor, int) or not minimo <= valor <= maximo:
        raise ValidationError(f"{ruta}: se espera un entero entre {minimo} y {maximo}")
    return valor


def _entero_en(datos: Mapping[str, Any], clave: str, minimo: int, maximo: int, defecto: int) -> int:
    if clave not in datos:
        return defecto
    return _entero_valor(datos[clave], f"limites.json.{clave}", minimo, maximo)


def _real_en(
    datos: Mapping[str, Any], clave: str, minimo: float, maximo: float, defecto: float
) -> float:
    if clave not in datos:
        return defecto
    valor = datos[clave]
    if (
        isinstance(valor, bool)
        or not isinstance(valor, (int, float))
        or not minimo <= valor <= maximo
    ):
        raise ValidationError(
            f"limites.json.{clave}: se espera un número entre {minimo} y {maximo}"
        )
    return float(valor)
