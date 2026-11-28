"""Árbol de comandos de la CLI `natxajo`, flujo de sesión y códigos de salida.

Flujo de cada comando: se validan los argumentos y la confirmación antes de pedir la contraseña;
después se inicia sesión, se reautentica si el comando es crítico y se llama al manejador. Durante
una ejecución de pruebas, Ctrl+C activa la cancelación cooperativa: el motor deja de enviar
solicitudes, conserva lo ya evaluado y la ejecución queda cerrada como cancelada.

Códigos de salida: 0 correcto; 1 hay resultados FAIL o ERROR; 2 uso incorrecto o plan no válido;
3 autorización o sesión denegada; 4 error técnico, cancelación o interrupción.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import signal
import sys
import threading
from collections.abc import Callable, Iterator, Sequence
from types import FrameType
from typing import Any, Final, TextIO

from natxajo_auditor.core.exceptions import AuthorizationError, NatxajoError, ValidationError
from natxajo_auditor.interfaces.cli import comandos as c
from natxajo_auditor.interfaces.cli.comandos import Contexto, Salida
from natxajo_auditor.kernel.kernel import Kernel

GRUPOS: Final[tuple[str, ...]] = (
    "forms",
    "auth",
    "security",
    "requests",
    "reports",
    "test",
    "targets",
    "accounts",
)
PREGUNTA_USUARIO: Final = "Usuario: "
PREGUNTA_CONTRASENA: Final = "Contraseña: "

Manejador = Callable[[Contexto, argparse.Namespace], Salida]


def es_comando_cli(primer_argumento: str) -> bool:
    return primer_argumento in GRUPOS


def construir_parser() -> argparse.ArgumentParser:
    raiz = argparse.ArgumentParser(
        prog="natxajo",
        description="Motor de pruebas HTTP y formularios de autenticación, con cuentas sintéticas.",
    )
    comunes = argparse.ArgumentParser(add_help=False)
    comunes.add_argument("--usuario", help="usuario de la plataforma (si se omite, se pregunta)")
    comunes.add_argument(
        "--contrasena-desde-entrada",
        action="store_true",
        help="lee la contraseña de la entrada estándar en lugar de pedirla",
    )
    comunes.add_argument("--json", action="store_true", help="salida en JSON")
    comunes.add_argument(
        "--confirmar", action="store_true", help="confirma las operaciones críticas"
    )
    ejecucion = argparse.ArgumentParser(add_help=False)
    ejecucion.add_argument("--formulario", help="identificador del formulario")
    ejecucion.add_argument("--objetivo", help="origen registrado, p. ej. http://127.0.0.1:8080")
    ejecucion.add_argument("--cuenta", action="append", help="cuenta sintética; puede repetirse")
    informe = argparse.ArgumentParser(add_help=False)
    informe.add_argument("--run", help="identificador de la ejecución (por defecto, la última)")

    arbol = _Arbol(raiz)
    arbol.hoja(
        ("forms", "list"), "lista los formularios configurados", c.formularios_listar, [comunes]
    )
    arbol.hoja(
        ("forms", "inspect"),
        "muestra campos, reglas y tipo de un formulario",
        c.formulario_inspeccionar,
        [comunes],
        posicional=("formulario",),
    )
    arbol.hoja(
        ("forms", "validate"),
        "comprueba configuración, cuentas y variables de entorno (sin red)",
        c.formulario_validar,
        [comunes],
        posicional=("formulario",),
    )
    arbol.hoja(
        ("forms", "test"),
        "ejecuta una suite de formularios contra el objetivo",
        c.formularios_probar,
        [comunes, ejecucion],
        ejecuta=True,
        suite=True,
    )
    arbol.hoja(
        ("auth", "test"),
        "ejecuta una suite de credenciales y cuentas sintéticas",
        c.auth_probar,
        [comunes, ejecucion],
        ejecuta=True,
        suite=True,
    )
    arbol.hoja(
        ("auth", "policy", "inspect"),
        "muestra la política de longitudes declarada del formulario (sin red)",
        c.auth_politica,
        [comunes, ejecucion],
    )
    arbol.hoja(
        ("auth", "mfa", "test"),
        "prueba el primer factor y el código de prueba del segundo",
        c.auth_mfa,
        [comunes, ejecucion],
        ejecuta=True,
    )
    arbol.hoja(
        ("auth", "sessions", "inspect"),
        "analiza HttpOnly, Secure y SameSite de las cookies de sesión",
        c.auth_sesiones,
        [comunes, ejecucion],
        ejecuta=True,
    )
    arbol.hoja(
        ("security", "rate-limit", "test"),
        "observa si el servidor bloquea tras intentos incorrectos (con tope)",
        c.seguridad_limite,
        [comunes, ejecucion],
        ejecuta=True,
    )
    arbol.hoja(
        ("security", "csrf", "test"),
        "comprueba que el servidor exige el token CSRF válido",
        c.seguridad_csrf,
        [comunes, ejecucion],
        ejecuta=True,
    )
    arbol.hoja(
        ("security", "response-check"),
        "compara respuestas de una cuenta existente y otra inexistente",
        c.seguridad_consistencia,
        [comunes, ejecucion],
        ejecuta=True,
    )
    arbol.hoja(
        ("requests", "history"),
        "lista las ejecuciones registradas",
        c.solicitudes_historial,
        [comunes],
        limite=True,
    )
    arbol.hoja(
        ("requests", "inspect"),
        "muestra los resultados de una ejecución",
        c.solicitudes_inspeccionar,
        [comunes, informe],
    )
    arbol.hoja(
        ("reports", "generate"),
        "genera el informe de una ejecución en JSON, CSV, HTML y TXT",
        c.informes_generar,
        [comunes, informe],
    )
    arbol.hoja(
        ("reports", "export"),
        "exporta el informe de una ejecución en un formato",
        c.informes_exportar,
        [comunes, informe],
        formato=True,
    )
    arbol.hoja(
        ("reports", "verify"),
        "verifica que los informes exportados no han cambiado",
        c.informes_verificar,
        [comunes],
    )
    arbol.hoja(
        ("test", "suites", "list"),
        "lista suites y procedimientos",
        c.catalogo_listar,
        [comunes],
    )
    arbol.hoja(
        ("test", "suites", "run"),
        "ejecuta una suite: validation, format, login-validation, credentials o synthetic-accounts",
        c.suites_ejecutar,
        [comunes, ejecucion],
        ejecuta=True,
        posicional=("suite",),
    )
    arbol.hoja(
        ("targets", "list"),
        "lista los objetivos registrados",
        c.objetivos_listar,
        [comunes],
    )
    arbol.hoja(
        ("targets", "add"),
        "registra un origen como objetivo de prueba autorizado",
        c.objetivos_registrar,
        [comunes],
        critico=True,
        posicional=("origen",),
    )
    arbol.hoja(
        ("accounts", "list"),
        "lista las cuentas sintéticas configuradas",
        c.cuentas_listar,
        [comunes],
    )
    return raiz


def ejecutar_cli(
    kernel: Kernel,
    argv: Sequence[str],
    *,
    salida: TextIO | None = None,
    errores: TextIO | None = None,
    entrada: TextIO | None = None,
    leer_contrasena: Callable[[str], str] | None = None,
) -> int:
    # Las corrientes y la lectura de contraseña se resuelven al llamar, no al importar el módulo.
    salida = salida or sys.stdout
    errores = errores or sys.stderr
    entrada = entrada or sys.stdin
    leer_contrasena = leer_contrasena or getpass.getpass
    parser = construir_parser()
    try:
        # argparse escribe sus avisos en stderr: se redirigen para que respeten la corriente indicada.
        with contextlib.redirect_stderr(errores):
            args = parser.parse_args(list(argv))
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else c.CODIGO_USO

    manejador: Manejador | None = getattr(args, "manejador", None)
    if manejador is None:
        parser.print_help(file=salida)
        return c.CODIGO_USO
    if args.critico and not args.confirmar:
        return _fallo(
            args,
            salida,
            errores,
            c.CODIGO_USO,
            "esta operación es crítica: añada --confirmar para continuar",
        )
    try:
        resultado = _con_sesion(kernel, args, salida, entrada, leer_contrasena, manejador)
    except ValidationError as exc:
        return _fallo(args, salida, errores, c.CODIGO_USO, str(exc))
    except AuthorizationError as exc:
        return _fallo(args, salida, errores, c.CODIGO_AUTORIZACION, str(exc))
    except KeyboardInterrupt:
        return _fallo(args, salida, errores, c.CODIGO_TECNICO, "operación interrumpida")
    except (NatxajoError, OSError) as exc:
        return _fallo(args, salida, errores, c.CODIGO_TECNICO, str(exc))
    _emitir(resultado, salida, bool(args.json))
    return resultado.codigo


def _con_sesion(
    kernel: Kernel,
    args: argparse.Namespace,
    salida: TextIO,
    entrada: TextIO,
    leer_contrasena: Callable[[str], str],
    manejador: Manejador,
) -> Salida:
    usuario = args.usuario
    if not usuario:
        salida.write(PREGUNTA_USUARIO)
        salida.flush()
        usuario = entrada.readline().strip()
    if args.contrasena_desde_entrada:
        contrasena = entrada.readline().rstrip("\r\n")
    else:
        contrasena = leer_contrasena(PREGUNTA_CONTRASENA)
    token = kernel.security.login(usuario, contrasena)
    try:
        if args.critico:
            # La reautenticación reutiliza la contraseña ya leída: no se pide dos veces.
            kernel.security.reauthenticate(token, contrasena)
        ctx = Contexto(kernel=kernel, token=token, cancelacion=threading.Event())
        with _interrupcion(ctx.cancelacion, activa=args.ejecuta):
            return manejador(ctx, args)
    finally:
        # Cerrar la sesión es best-effort: no debe ocultar el error real de la operación.
        with contextlib.suppress(NatxajoError):
            kernel.security.logout(token)


@contextlib.contextmanager
def _interrupcion(cancelacion: threading.Event, *, activa: bool) -> Iterator[None]:
    """Durante una ejecución de pruebas, Ctrl+C activa la cancelación en vez de interrumpir."""
    if not activa:
        yield
        return

    def manejar(_senal: int, _marco: FrameType | None) -> None:
        cancelacion.set()

    try:
        previo = signal.signal(signal.SIGINT, manejar)
    except ValueError:
        # Fuera del hilo principal no se pueden instalar señales: se mantiene el comportamiento normal.
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previo)


def _emitir(resultado: Salida, salida: TextIO, como_json: bool) -> None:
    if como_json:
        salida.write(json.dumps(resultado.datos, ensure_ascii=False, indent=2, default=str) + "\n")
    else:
        salida.write(resultado.texto + "\n")


def _fallo(
    args: argparse.Namespace,
    salida: TextIO,
    errores: TextIO,
    codigo: int,
    mensaje: str,
) -> int:
    if getattr(args, "json", False):
        salida.write(json.dumps({"error": mensaje, "codigo": codigo}, ensure_ascii=False) + "\n")
    else:
        errores.write(f"natxajo: {mensaje}\n")
    return codigo


class _Arbol:
    """Jerarquía grupo → subgrupo → acción construida con argparse, sin repetir código."""

    def __init__(self, raiz: argparse.ArgumentParser) -> None:
        self._niveles: dict[tuple[str, ...], Any] = {
            (): raiz.add_subparsers(dest="grupo", metavar="grupo")
        }

    def _nivel(self, prefijo: tuple[str, ...]) -> Any:
        if prefijo not in self._niveles:
            padre = self._nivel(prefijo[:-1])
            grupo = padre.add_parser(prefijo[-1], help=f"grupo {prefijo[-1]}")
            self._niveles[prefijo] = grupo.add_subparsers(
                dest=f"nivel_{len(prefijo)}", metavar="acción"
            )
        return self._niveles[prefijo]

    def hoja(
        self,
        ruta: tuple[str, ...],
        ayuda: str,
        manejador: Manejador,
        padres: list[argparse.ArgumentParser],
        *,
        critico: bool = False,
        ejecuta: bool = False,
        suite: bool = False,
        posicional: tuple[str, ...] = (),
        limite: bool = False,
        formato: bool = False,
    ) -> None:
        parser = self._nivel(ruta[:-1]).add_parser(ruta[-1], help=ayuda, parents=padres)
        for nombre in posicional:
            parser.add_argument(nombre)
        if suite:
            parser.add_argument("--suite", required=True, help="nombre de la suite")
        if limite:
            parser.add_argument("--limite", type=int, default=20, help="número de ejecuciones")
        if formato:
            parser.add_argument(
                "--format",
                dest="formato",
                required=True,
                choices=c.FORMATOS,
                help="formato del informe",
            )
        # Una ejecución de pruebas es siempre crítica y además atiende a Ctrl+C con cancelación.
        parser.set_defaults(
            manejador=manejador,
            critico=critico or ejecuta,
            ejecuta=ejecuta,
        )
