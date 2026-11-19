"""Punto de entrada compartido por main.py, launcher.ps1 y el comando natxajo-auditor."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from natxajo_auditor import __version__
from natxajo_auditor.core.exceptions import NatxajoError
from natxajo_auditor.interfaces.terminal.app import run_terminal
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="natxajo-auditor",
        description="Plataforma modular de auditoría defensiva de autenticación.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None, project_root: Path | None = None) -> int:
    # Se analizan los argumentos antes de tocar el disco: --version no crea archivos.
    build_parser().parse_args(argv)
    root = (project_root or Path.cwd()).resolve()
    kernel = Kernel(RuntimeContext(project_root=root))
    try:
        kernel.start()
    except (NatxajoError, OSError) as exc:
        print(f"No se pudo iniciar la plataforma: {exc}", file=sys.stderr)
        return 1
    try:
        return run_terminal(kernel)
    finally:
        kernel.stop()
