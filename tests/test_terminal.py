from collections.abc import Callable, Iterable
from pathlib import Path

from natxajo_auditor.interfaces.terminal.app import run_terminal
from natxajo_auditor.kernel.kernel import SERVICE_VERSIONS, Kernel
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER


def _scripted(answers: Iterable[str]) -> Callable[[str], str]:
    iterator = iter(answers)

    def read(prompt: str) -> str:
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None

    return read


def test_terminal_lists_versions_and_exits(
    kernel: Kernel, admin: tuple[str, str], make_manifest: Callable[..., Path]
) -> None:
    make_manifest(kernel.context.versions_dir, "0.1.0")
    lines: list[str] = []
    code = run_terminal(
        kernel,
        read=_scripted([ADMIN_USER, "2", "0"]),
        write=lines.append,
        read_secret=_scripted([ADMIN_PASSWORD]),
    )
    assert code == 0
    assert any(line.startswith("- 0.1.0 | development") for line in lines)


def test_terminal_loads_version_after_reauthentication_and_confirmation(
    kernel: Kernel, admin: tuple[str, str], make_manifest: Callable[..., Path]
) -> None:
    make_manifest(kernel.context.versions_dir, "0.1.0")
    lines: list[str] = []
    run_terminal(
        kernel,
        read=_scripted([ADMIN_USER, "17", "4", "sí", "0.1.0", "4", "sí", "9.9.9", "0"]),
        write=lines.append,
        read_secret=_scripted([ADMIN_PASSWORD, ADMIN_PASSWORD]),
    )
    assert kernel.services.get(SERVICE_VERSIONS).active == "0.1.0"
    assert any(line.startswith("Error:") for line in lines)


def test_critical_option_without_reauthentication_is_refused(
    kernel: Kernel, admin: tuple[str, str], make_manifest: Callable[..., Path]
) -> None:
    make_manifest(kernel.context.versions_dir, "0.1.0")
    lines: list[str] = []
    run_terminal(
        kernel,
        read=_scripted([ADMIN_USER, "4", "sí", "0.1.0", "0"]),
        write=lines.append,
        read_secret=_scripted([ADMIN_PASSWORD]),
    )
    assert kernel.services.get(SERVICE_VERSIONS).active is None
    assert any("reautentique la sesión" in line for line in lines)


def test_unknown_option_is_reported_and_eof_exits_cleanly(
    kernel: Kernel, admin: tuple[str, str]
) -> None:
    lines: list[str] = []
    code = run_terminal(
        kernel,
        read=_scripted([ADMIN_USER, "zz"]),
        write=lines.append,
        read_secret=_scripted([ADMIN_PASSWORD]),
    )
    assert code == 0
    assert "Opción no válida" in lines


def test_three_failed_logins_exit_with_error(kernel: Kernel, admin: tuple[str, str]) -> None:
    lines: list[str] = []
    code = run_terminal(
        kernel,
        read=_scripted([ADMIN_USER] * 3),
        write=lines.append,
        read_secret=_scripted(["incorrecta-uno", "incorrecta-dos", "incorrecta-tres"]),
    )
    assert code == 1
    assert "Demasiados intentos fallidos. Saliendo." in lines


def test_first_run_creates_the_administrator(kernel: Kernel) -> None:
    lines: list[str] = []
    code = run_terminal(
        kernel,
        read=_scripted(["admin_inicial", "admin_inicial", "0"]),
        write=lines.append,
        read_secret=_scripted([ADMIN_PASSWORD, ADMIN_PASSWORD, ADMIN_PASSWORD]),
    )
    assert code == 0
    assert kernel.security.has_accounts()
    assert kernel.security.accounts.get("admin_inicial").roles == ("administrador",)
    assert any("Cuenta de administrador creada" in line for line in lines)


def test_bootstrap_refuses_mismatched_passwords(kernel: Kernel) -> None:
    lines: list[str] = []
    code = run_terminal(
        kernel,
        read=_scripted(["admin_inicial"]),
        write=lines.append,
        read_secret=_scripted([ADMIN_PASSWORD, "otra-contraseña-x"]),
    )
    assert code == 1
    assert "Error: las contraseñas no coinciden" in lines
    assert not kernel.security.has_accounts()


def test_auditor_menu_hides_options_it_cannot_use(kernel: Kernel, admin: tuple[str, str]) -> None:
    kernel.security.create_account("auditor_prueba", ADMIN_PASSWORD, ["auditor"])
    lines: list[str] = []
    run_terminal(
        kernel,
        read=_scripted(["auditor_prueba", "4", "0"]),
        write=lines.append,
        read_secret=_scripted([ADMIN_PASSWORD]),
    )
    menu = "\n".join(lines)
    assert "Estado del sistema" in menu
    assert "Cargar una versión" not in menu
    assert "Opción no disponible para su cuenta" in lines
