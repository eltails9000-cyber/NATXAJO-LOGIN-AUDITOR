"""Servicio de pruebas HTTP: operaciones protegidas por el guardián, persistencia y auditoría.

Orden de cada ejecución: se valida el plan (objetivo registrado, formulario, cuentas sintéticas,
credenciales en el entorno y límites) antes de abrir nada. Después se abre la ejecución y su evento
de auditoría en una transacción, se ejecutan las peticiones sin tocar la base de datos y, por último,
se cierra la ejecución con sus resultados en otra transacción. Si la ejecución falla a mitad, queda
cerrada como cancelada, nunca abierta.

Los permisos de registrar objetivos y de ejecutar pruebas son críticos: el guardián exige
confirmación y reautenticación. Leer resultados y exportar informes no lo son.
"""

from __future__ import annotations

import dataclasses
import os
import threading
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

from natxajo_auditor.core.contracts import (
    HTTP_EXPORT_PERMISSION,
    HTTP_READ_PERMISSION,
    HTTP_RUN_PERMISSION,
    HTTP_TARGET_PERMISSION,
    OperationGate,
)
from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.core.utilities import Clock, atomic_write_bytes, sha256_bytes, to_iso
from natxajo_auditor.pruebas.cliente import ClienteHttp
from natxajo_auditor.pruebas.cuentas import resolver_credenciales
from natxajo_auditor.pruebas.esquema import (
    ARCHIVO_FORMULARIOS,
    cargar_cuentas,
    cargar_formularios,
    cargar_limites,
)
from natxajo_auditor.pruebas.informes import FORMATOS, renderizar
from natxajo_auditor.pruebas.matrices import generar_casos, suites_que_componen
from natxajo_auditor.pruebas.modelo import (
    CONTRASENA,
    IDENTIDAD,
    PROCEDURES,
    SUITES,
    Caso,
    CuentaSintetica,
    Formulario,
    Limites,
    ResultadoCaso,
    TipoFormulario,
)
from natxajo_auditor.pruebas.motor import Contexto, Presupuesto, ejecutar_casos, numerar
from natxajo_auditor.pruebas.objetivos import esta_permitido, normalizar_origen
from natxajo_auditor.pruebas.procedimientos import PROCEDIMIENTOS
from natxajo_auditor.pruebas.repositorio import RepositorioPruebas
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database

MAX_HISTORIAL: Final = 200
MAX_NOMBRE_INFORME: Final = 80


class PruebasService:
    def __init__(
        self,
        *,
        database: Database,
        audit: AuditLog,
        gate: OperationGate,
        clock: Clock,
        config_dir: Path,
        reports_dir: Path,
        platform_version: str,
        entorno: Mapping[str, str] | None = None,
    ) -> None:
        self._db = database
        self._audit = audit
        self._gate = gate
        self._clock = clock
        self._repo = RepositorioPruebas(database)
        self._config_dir = config_dir / "pruebas"
        self._reports_dir = reports_dir / "pruebas"
        self._version = platform_version
        # Copia del entorno al crear el servicio: las credenciales se leen de aquí y no se guardan.
        self._entorno: dict[str, str] = dict(os.environ) if entorno is None else dict(entorno)

    # ----- Objetivos permitidos -------------------------------------------------------------

    def registrar_objetivo(self, token: str, origen: str, *, confirmed: bool) -> dict[str, object]:
        def operacion() -> dict[str, object]:
            usuario = self._gate.username_for(token)
            normalizado = normalizar_origen(origen).texto
            momento = to_iso(self._clock())
            with self._db.transaction() as conexion:
                self._repo.registrar_objetivo(conexion, normalizado, usuario, momento)
                self._audit.record(
                    "pruebas.objetivo_registrado", {"origen": normalizado}, conexion, actor=usuario
                )
            return {"origen": normalizado, "registrado_en": momento, "registrado_por": usuario}

        return self._gate.run(token, HTTP_TARGET_PERMISSION, operacion, confirmed=confirmed)

    def objetivos(self, token: str) -> list[dict[str, object]]:
        return self._gate.run(token, HTTP_READ_PERMISSION, self._repo.objetivos)

    # ----- Configuración: formularios, cuentas y límites (solo lectura) ----------------------

    def formularios(self, token: str) -> list[dict[str, object]]:
        def operacion() -> list[dict[str, object]]:
            return [_resumen_formulario(f) for f in cargar_formularios(self._config_dir).values()]

        return self._gate.run(token, HTTP_READ_PERMISSION, operacion)

    def formulario(self, token: str, formulario_id: str) -> dict[str, object]:
        return self._gate.run(
            token,
            HTTP_READ_PERMISSION,
            lambda: _detalle_formulario(self._formulario(formulario_id)),
        )

    def politica(self, token: str, formulario_id: str) -> dict[str, object]:
        def operacion() -> dict[str, object]:
            formulario = self._formulario(formulario_id)
            return {
                "formulario": formulario.id,
                "identidad": list(formulario.longitudes.get(IDENTIDAD, (1, 254))),
                "contrasena": list(formulario.longitudes.get(CONTRASENA, (1, 256))),
                "fuente": "declarada en formularios.json; no se comprueba contra el objetivo",
            }

        return self._gate.run(token, HTTP_READ_PERMISSION, operacion)

    def cuentas(self, token: str) -> list[dict[str, object]]:
        def operacion() -> list[dict[str, object]]:
            return [self._resumen_cuenta(c) for c in cargar_cuentas(self._config_dir).values()]

        return self._gate.run(token, HTTP_READ_PERMISSION, operacion)

    def validar(self, token: str, formulario_id: str) -> list[dict[str, object]]:
        """Comprobaciones sin red: cuentas, variables de entorno, código MFA y token CSRF."""

        def operacion() -> list[dict[str, object]]:
            formulario = self._formulario(formulario_id)
            cuentas = list(cargar_cuentas(self._config_dir).values())
            controles: list[dict[str, object]] = [
                _control(
                    "cuentas-sinteticas",
                    bool(cuentas),
                    f"{len(cuentas)} cuenta(s) configurada(s)"
                    if cuentas
                    else "no hay cuentas sintéticas en cuentas.json",
                )
            ]
            faltan = sorted(
                {
                    c.variable_contrasena
                    for c in cuentas
                    if not self._entorno.get(c.variable_contrasena)
                }
            )
            controles.append(
                _control(
                    "contrasenas-en-entorno",
                    bool(cuentas) and not faltan,
                    "faltan variables: " + ", ".join(faltan)
                    if faltan
                    else "todas las variables de contraseña están definidas",
                )
            )
            if formulario.mfa is None:
                controles.append(_no_aplica("codigo-mfa", "el formulario no es de tipo MFA"))
            else:
                con_codigo = [
                    c for c in cuentas if c.variable_mfa and self._entorno.get(c.variable_mfa)
                ]
                controles.append(
                    _control(
                        "codigo-mfa",
                        bool(con_codigo),
                        "hay código MFA de prueba en el entorno"
                        if con_codigo
                        else "ninguna cuenta tiene código MFA definido en el entorno",
                    )
                )
            if formulario.csrf is None:
                controles.append(_no_aplica("csrf", "el formulario no declara token CSRF"))
            else:
                controles.append(
                    _control("csrf", True, f"token declarado en el campo '{formulario.csrf.campo}'")
                )
            return controles

        return self._gate.run(token, HTTP_READ_PERMISSION, operacion)

    def catalogo(self, token: str) -> dict[str, object]:
        return self._gate.run(
            token,
            HTTP_READ_PERMISSION,
            lambda: {"suites": dict(SUITES), "procedimientos": dict(PROCEDURES)},
        )

    # ----- Ejecución ------------------------------------------------------------------------

    def ejecutar_suite(
        self,
        token: str,
        *,
        suite: str,
        objetivo: str,
        formulario_id: str,
        cuentas: Sequence[str],
        confirmed: bool,
        cancelacion: threading.Event | None = None,
    ) -> dict[str, object]:
        suites_que_componen(suite)
        return self._ejecutar(
            token,
            nombre=suite,
            procedimiento=False,
            objetivo=objetivo,
            formulario_id=formulario_id,
            cuentas=cuentas,
            confirmed=confirmed,
            cancelacion=cancelacion,
        )

    def ejecutar_procedimiento(
        self,
        token: str,
        *,
        nombre: str,
        objetivo: str,
        formulario_id: str,
        cuenta: str,
        confirmed: bool,
        cancelacion: threading.Event | None = None,
    ) -> dict[str, object]:
        if nombre not in PROCEDIMIENTOS:
            opciones = ", ".join(sorted(PROCEDIMIENTOS))
            raise ValidationError(f"procedimiento no conocido; use uno de: {opciones}")
        return self._ejecutar(
            token,
            nombre=nombre,
            procedimiento=True,
            objetivo=objetivo,
            formulario_id=formulario_id,
            cuentas=[cuenta],
            confirmed=confirmed,
            cancelacion=cancelacion,
        )

    def historial(self, token: str, limite: int = 20) -> list[dict[str, object]]:
        if not 1 <= limite <= MAX_HISTORIAL:
            raise ValidationError(f"el límite del historial debe estar entre 1 y {MAX_HISTORIAL}")
        return self._gate.run(token, HTTP_READ_PERMISSION, lambda: self._repo.ejecuciones(limite))

    def inspeccionar(self, token: str, run_id: str) -> dict[str, object]:
        def operacion() -> dict[str, object]:
            return self._ejecucion_o_error(run_id)

        return self._gate.run(token, HTTP_READ_PERMISSION, operacion)

    # ----- Informes -------------------------------------------------------------------------

    def exportar(self, token: str, run_id: str, formato: str) -> dict[str, object]:
        if formato not in FORMATOS:
            raise ValidationError(f"formato no admitido; use uno de: {', '.join(FORMATOS)}")

        def operacion() -> dict[str, object]:
            usuario = self._gate.username_for(token)
            ejecucion = self._ejecucion_o_error(run_id)
            if ejecucion["estado"] == "en_curso":
                raise ValidationError("la ejecución sigue en curso; no se exporta todavía")
            generado = to_iso(self._clock())
            meta = {
                "solicitado_por": usuario,
                "generado_en": generado,
                "version_plataforma": self._version,
            }
            contenido = renderizar(ejecucion, meta, formato)
            digest = sha256_bytes(contenido)
            export_id = str(uuid.uuid4())
            relativa = f"{run_id}-{export_id}.{formato}"
            destino = self._reports_dir / relativa
            destino.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(destino, contenido)
            with self._db.transaction() as conexion:
                self._repo.registrar_exportacion(
                    conexion,
                    export_id=export_id,
                    run_id=run_id,
                    formato=formato,
                    usuario=usuario,
                    ruta_relativa=relativa,
                    sha256=digest,
                    tamano=len(contenido),
                    creado_en=generado,
                )
                self._audit.record(
                    "pruebas.informe_exportado",
                    {"run_id": run_id, "formato": formato, "sha256": digest},
                    conexion,
                    actor=usuario,
                )
            return {
                "id": export_id,
                "run_id": run_id,
                "formato": formato,
                "ruta": str(destino),
                "sha256": digest,
                "tamano_bytes": len(contenido),
            }

        return self._gate.run(token, HTTP_EXPORT_PERMISSION, operacion)

    def verificar_informes(self, token: str) -> list[dict[str, object]]:
        """Estado de cada informe exportado: correcto, alterado, faltante o fuera de la carpeta."""

        def operacion() -> list[dict[str, object]]:
            raiz = self._reports_dir.resolve()
            resultados: list[dict[str, object]] = []
            for exportacion in self._repo.exportaciones():
                ruta = (raiz / str(exportacion["ruta"])).resolve()
                if not ruta.is_relative_to(raiz):
                    estado = "fuera_de_carpeta"
                elif not ruta.is_file():
                    estado = "faltante"
                else:
                    contenido = ruta.read_bytes()
                    registrado_ok = (
                        sha256_bytes(contenido) == exportacion["sha256"]
                        and len(contenido) == exportacion["tamano_bytes"]
                    )
                    estado = "correcto" if registrado_ok else "alterado"
                resultados.append({**exportacion, "estado": estado})
            return resultados

        return self._gate.run(token, HTTP_READ_PERMISSION, operacion)

    # ----- Internos -------------------------------------------------------------------------

    def _ejecutar(
        self,
        token: str,
        *,
        nombre: str,
        procedimiento: bool,
        objetivo: str,
        formulario_id: str,
        cuentas: Sequence[str],
        confirmed: bool,
        cancelacion: threading.Event | None,
    ) -> dict[str, object]:
        def operacion() -> dict[str, object]:
            usuario = self._gate.username_for(token)
            origen = normalizar_origen(objetivo)
            if not esta_permitido(origen, self._repo.objetivos_registrados()):
                raise AuthorizationError("el objetivo no está registrado como permitido")
            formulario = self._formulario(formulario_id)
            limites = cargar_limites(self._config_dir)
            seleccion = self._seleccion(cuentas, limites)
            for cuenta in seleccion:
                if self._repo.es_cuenta_de_plataforma(cuenta.usuario):
                    raise ValidationError(
                        f"la cuenta '{cuenta.id}' coincide con una cuenta de la plataforma"
                    )
            credenciales = resolver_credenciales(
                seleccion, self._entorno, con_mfa=procedimiento and nombre == "mfa"
            )
            casos: list[Caso] = []
            if not procedimiento:
                casos = generar_casos(
                    nombre,
                    _con_marcador_mfa(formulario),
                    [(c.id, credenciales[c.id]) for c in seleccion],
                )

            run_id = str(uuid.uuid4())
            iniciado = to_iso(self._clock())
            planificados = len(casos)
            with self._db.transaction() as conexion:
                self._repo.abrir_ejecucion(
                    conexion,
                    run_id=run_id,
                    suite=nombre,
                    origen=origen.texto,
                    esquema_sha256=self._huella_formularios(),
                    usuario=usuario,
                    iniciado_en=iniciado,
                    casos=planificados,
                )
                self._audit.record(
                    "pruebas.ejecucion_iniciada",
                    {
                        "run_id": run_id,
                        "suite": nombre,
                        "origen": origen.texto,
                        "formulario": formulario.id,
                        "casos": planificados,
                    },
                    conexion,
                    actor=usuario,
                )

            presupuesto = Presupuesto(limites.max_solicitudes)
            cancelacion_activa = cancelacion if cancelacion is not None else threading.Event()
            try:
                contexto = Contexto(
                    cliente=ClienteHttp(origen, limites.timeout_s),
                    limites=limites,
                    presupuesto=presupuesto,
                    cancelacion=cancelacion_activa,
                )
                if procedimiento:
                    primera = seleccion[0]
                    resultados = numerar(
                        PROCEDIMIENTOS[nombre](
                            contexto, formulario, credenciales[primera.id], primera.id
                        )
                    )
                else:
                    resultados = ejecutar_casos(casos, contexto)
            except BaseException:
                # Un fallo a mitad deja la ejecución cerrada como cancelada, nunca en curso.
                self._cerrar(run_id, usuario, "cancelada", [], presupuesto.usadas)
                raise
            estado = "cancelada" if cancelacion_activa.is_set() else "completada"
            self._cerrar(run_id, usuario, estado, resultados, presupuesto.usadas)
            return self._ejecucion_o_error(run_id)

        return self._gate.run(
            token,
            HTTP_RUN_PERMISSION,
            operacion,
            confirmed=confirmed,
        )

    def _cerrar(
        self,
        run_id: str,
        usuario: str,
        estado: str,
        resultados: Sequence[ResultadoCaso],
        solicitudes: int,
    ) -> None:
        cuenta = Counter(r.resultado.value for r in resultados)
        with self._db.transaction() as conexion:
            self._repo.cerrar_ejecucion(
                conexion,
                run_id=run_id,
                estado=estado,
                terminado_en=to_iso(self._clock()),
                solicitudes=solicitudes,
                resultados=resultados,
            )
            self._audit.record(
                "pruebas.ejecucion_terminada",
                {
                    "run_id": run_id,
                    "estado": estado,
                    "pass": cuenta.get("PASS", 0),
                    "fail": cuenta.get("FAIL", 0),
                    "blocked": cuenta.get("BLOCKED", 0),
                    "error": cuenta.get("ERROR", 0),
                    "skipped": cuenta.get("SKIPPED", 0),
                    "requests": solicitudes,
                },
                conexion,
                actor=usuario,
            )

    def _formulario(self, formulario_id: str) -> Formulario:
        formularios = cargar_formularios(self._config_dir)
        if formulario_id not in formularios:
            raise ValidationError(f"formulario no encontrado: '{formulario_id}'")
        return formularios[formulario_id]

    def _seleccion(self, ids: Sequence[str], limites: Limites) -> list[CuentaSintetica]:
        if not ids:
            raise ValidationError("indique al menos una cuenta sintética")
        unicas = list(dict.fromkeys(ids))
        if len(unicas) > limites.max_cuentas:
            raise ValidationError(f"el máximo de cuentas por ejecución es {limites.max_cuentas}")
        configuradas = cargar_cuentas(self._config_dir)
        faltan = [i for i in unicas if i not in configuradas]
        if faltan:
            raise ValidationError("cuenta sintética no configurada: " + ", ".join(faltan))
        return [configuradas[i] for i in unicas]

    def _ejecucion_o_error(self, run_id: str) -> dict[str, object]:
        try:
            uuid.UUID(run_id)
        except ValueError as exc:
            raise ValidationError("identificador de ejecución no válido") from exc
        ejecucion = self._repo.ejecucion(run_id)
        if ejecucion is None:
            raise ValidationError("ejecución no encontrada")
        return ejecucion

    def _huella_formularios(self) -> str:
        ruta = self._config_dir / ARCHIVO_FORMULARIOS
        return sha256_bytes(ruta.read_bytes() if ruta.is_file() else b"")

    def _resumen_cuenta(self, cuenta: CuentaSintetica) -> dict[str, object]:
        return {
            "id": cuenta.id,
            "usuario": cuenta.usuario,
            "correo": cuenta.correo,
            "variable_contrasena": cuenta.variable_contrasena,
            "contrasena_en_entorno": bool(self._entorno.get(cuenta.variable_contrasena)),
            "variable_mfa": cuenta.variable_mfa,
            "mfa_en_entorno": bool(cuenta.variable_mfa and self._entorno.get(cuenta.variable_mfa)),
        }


def _con_marcador_mfa(formulario: Formulario) -> Formulario:
    """En un formulario MFA, el primer factor correcto se reconoce por el marcador del segundo."""
    if formulario.mfa is None:
        return formulario
    reglas = dataclasses.replace(
        formulario.reglas, exito=(*formulario.reglas.exito, formulario.mfa.marcador)
    )
    return dataclasses.replace(formulario, reglas=reglas)


def _resumen_formulario(formulario: Formulario) -> dict[str, object]:
    return {
        "id": formulario.id,
        "tipo": formulario.tipo.value,
        "ruta": formulario.ruta,
        "csrf": formulario.csrf is not None,
        "mfa": formulario.tipo is TipoFormulario.USUARIO_CONTRASENA_MFA,
    }


def _detalle_formulario(formulario: Formulario) -> dict[str, object]:
    return {
        "id": formulario.id,
        "tipo": formulario.tipo.value,
        "ruta": formulario.ruta,
        "campos": dict(formulario.campos),
        "longitudes": {rol: list(par) for rol, par in formulario.longitudes.items()},
        "extra": dict(formulario.extra),
        "csrf": None
        if formulario.csrf is None
        else {"campo": formulario.csrf.campo, "pagina": formulario.csrf.pagina},
        "mfa": None
        if formulario.mfa is None
        else {"campo": formulario.mfa.campo, "ruta": formulario.mfa.ruta},
        "respuesta": {
            "exito": list(formulario.reglas.exito),
            "fallo": list(formulario.reglas.fallo),
            "bloqueo": list(formulario.reglas.bloqueo),
            "ruta_login": formulario.reglas.ruta_login,
        },
    }


def _control(nombre: str, cumple: bool, detalle: str) -> dict[str, object]:
    return {"control": nombre, "estado": "PASS" if cumple else "FAIL", "detalle": detalle}


def _no_aplica(nombre: str, detalle: str) -> dict[str, object]:
    return {"control": nombre, "estado": "SKIPPED", "detalle": detalle}
