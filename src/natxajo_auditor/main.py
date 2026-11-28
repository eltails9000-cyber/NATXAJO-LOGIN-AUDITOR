"""Punto de entrada compartido por main.py, launcher.ps1 y el comando natxajo-auditor."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from natxajo_auditor import __version__
from natxajo_auditor.core.exceptions import NatxajoError
from natxajo_auditor.interfaces.cli.app import ejecutar_cli, es_comando_cli
from natxajo_auditor.interfaces.gui import run_gui
from natxajo_auditor.interfaces.terminal.app import run_terminal
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="natxajo-auditor",
        description="Plataforma modular de auditoría defensiva de autenticación.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--gui",
        action="store_true",
        help="abre la interfaz gráfica local (127.0.0.1) en lugar de la terminal",
    )
    parser.add_argument(
        "--sin-navegador",
        action="store_true",
        help="con --gui, muestra la dirección sin abrir el navegador",
    )
    return parser


def main(argv: Sequence[str] | None = None, project_root: Path | None = None) -> int:
    lista = list(sys.argv[1:] if argv is None else argv)
    if lista and es_comando_cli(lista[0]):
        return _cli(lista, project_root)
    # Se analizan los argumentos antes de tocar el disco: --version no crea archivos.
    parser = build_parser()
    args = parser.parse_args(lista)
    if args.sin_navegador and not args.gui:
        parser.error("--sin-navegador solo tiene efecto junto con --gui")
    root = (project_root or Path.cwd()).resolve()
    kernel = Kernel(RuntimeContext(project_root=root))
    try:
        kernel.start()
    except (NatxajoError, OSError) as exc:
        print(f"No se pudo iniciar la plataforma: {exc}", file=sys.stderr)
        return 1
    try:
        if args.gui:
            return run_gui(kernel, open_browser=not args.sin_navegador)
        return run_terminal(kernel)
    finally:
        kernel.stop()


def _cli(argv: Sequence[str], project_root: Path | None) -> int:
    """Comandos `natxajo <grupo> <acción>`: mismo núcleo, mismas reglas que la GUI y la terminal."""
    root = (project_root or Path.cwd()).resolve()
    kernel = Kernel(RuntimeContext(project_root=root))
    try:
        kernel.start()
    except (NatxajoError, OSError) as exc:
        print(f"No se pudo iniciar la plataforma: {exc}", file=sys.stderr)
        return 4
    try:
        return ejecutar_cli(kernel, argv)
    finally:
        kernel.stop()
