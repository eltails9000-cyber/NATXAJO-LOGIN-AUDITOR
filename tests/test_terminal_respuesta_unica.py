"""La terminal no revela por qué se rechaza un inicio de sesión.

Una contraseña correcta en una cuenta con el límite de sesiones alcanzado debe producir exactamente
la misma salida que una contraseña incorrecta. Si no fuera así, quien tuviera acceso a la terminal
podría comprobar contraseñas contra una cuenta llena. El motivo real queda en la auditoría.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from natxajo_auditor.interfaces.terminal.app import run_terminal
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.security.sessions import MAX_CONCURRENT_SESSIONS
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER


def _scripted(answers: Iterable[str]) -> Callable[[str], str]:
    iterator = iter(answers)

    def read(prompt: str) -> str:
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None

    return read


def _intento(kernel: Kernel, contrasenas: list[str]) -> list[str]:
    salida: list[str] = []
    run_terminal(
        kernel,
        read=_scripted([ADMIN_USER] * len(contrasenas)),
        write=salida.append,
        read_secret=_scripted(contrasenas),
    )
    return salida


def test_a_correct_password_at_the_session_limit_looks_like_a_wrong_one(
    kernel: Kernel, admin: tuple[str, str]
) -> None:
    for _ in range(MAX_CONCURRENT_SESSIONS):
        kernel.security.login(ADMIN_USER, ADMIN_PASSWORD)

    con_limite = _intento(kernel, [ADMIN_PASSWORD])
    contrasena_incorrecta = _intento(kernel, ["incorrecta-uno"])

    assert con_limite == contrasena_incorrecta
    assert not any("sesiones simultáneas" in linea for linea in con_limite)
    # El motivo real sigue registrado.
    assert len(kernel.audit.events_of_type("session.limit_reached")) >= 1
