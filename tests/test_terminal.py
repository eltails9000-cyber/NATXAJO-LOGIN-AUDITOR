from collections.abc import Callable, Iterable
from pathlib import Path

from natxajo_auditor.interfaces.terminal.app import run_terminal
from natxajo_auditor.kernel.kernel import SERVICE_VERSIONS, Kernel


def _scripted(answers: Iterable[str]) -> Callable[[str], str]:
    iterator = iter(answers)

    def read(prompt: str) -> str:
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None

    return read


def test_terminal_lists_versions_and_exits(
    kernel: Kernel, make_manifest: Callable[..., Path]
) -> None:
    make_manifest(kernel.context.versions_dir, "0.1.0")
    lines: list[str] = []
    code = run_terminal(kernel, read=_scripted(["2", "0"]), write=lines.append)
    assert code == 0
    assert any(line.startswith("- 0.1.0 | development") for line in lines)


def test_terminal_loads_version_and_reports_errors(
    kernel: Kernel, make_manifest: Callable[..., Path]
) -> None:
    make_manifest(kernel.context.versions_dir, "0.1.0")
    lines: list[str] = []
    run_terminal(kernel, read=_scripted(["4", "0.1.0", "4", "9.9.9", "0"]), write=lines.append)
    assert kernel.services.get(SERVICE_VERSIONS).active == "0.1.0"
    assert any(line.startswith("Error:") for line in lines)


def test_unknown_option_is_reported_and_eof_exits_cleanly(kernel: Kernel) -> None:
    lines: list[str] = []
    code = run_terminal(kernel, read=_scripted(["zz"]), write=lines.append)
    assert code == 0
    assert "Opción no válida" in lines
