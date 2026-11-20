from collections.abc import Callable, Iterable
from pathlib import Path

from natxajo_auditor.interfaces.terminal.app import run_terminal
from natxajo_auditor.kernel.kernel import Kernel
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER


def _scripted(answers: Iterable[str]) -> Callable[[str], str]:
    iterator = iter(answers)

    def read(prompt: str) -> str:
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None

    return read


def test_terminal_enables_module_and_lists_it(
    kernel: Kernel, admin: tuple[str, str], make_module: Callable[..., Path]
) -> None:
    make_module(kernel.context.modules_dir, "base_mod")
    lines: list[str] = []
    run_terminal(
        kernel,
        read=_scripted([ADMIN_USER, "17", "11", "sí", "base_mod", "10", "0"]),
        write=lines.append,
        read_secret=_scripted([ADMIN_PASSWORD, ADMIN_PASSWORD]),
    )
    assert kernel.modules.is_enabled("base_mod")
    assert any("Habilitados: base_mod" in line for line in lines)
    assert any(line.startswith("- base_mod 0.1.0 | habilitado") for line in lines)


def test_terminal_reports_diagnostics_for_broken_module(
    kernel: Kernel, admin: tuple[str, str], make_module: Callable[..., Path]
) -> None:
    make_module(kernel.context.modules_dir, "roto_mod", permissions=["mal.permiso"])
    lines: list[str] = []
    run_terminal(
        kernel,
        read=_scripted([ADMIN_USER, "13", "0"]),
        write=lines.append,
        read_secret=_scripted([ADMIN_PASSWORD]),
    )
    assert any(line.startswith("- roto_mod:") for line in lines)
