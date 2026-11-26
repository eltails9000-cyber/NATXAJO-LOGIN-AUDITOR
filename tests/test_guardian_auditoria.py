"""Auditoría del guardián: éxitos, fallos y denegaciones, sin duplicar eventos ni ocultar resultados.

- Una operación autorizada que termina bien registra `operation.executed` una vez.
- Una operación autorizada que falla registra `operation.failed` con solo el tipo del error, y
  el llamador recibe su excepción original.
- Un error al escribir en la auditoría no oculta ni el resultado ni el error de la operación.
- Una denegación dentro de una operación se registra una sola vez.
"""

from __future__ import annotations

import logging

import pytest

from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.storage.audit import AuditLog
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER

READ = "auditoria:nucleo:evento:leer"
AUDITOR = "auditor_acme"
PASSWORD = "contraseña-de-prueba-7"


def _token(kernel: Kernel) -> str:
    return kernel.security.login(ADMIN_USER, ADMIN_PASSWORD)


def _count(kernel: Kernel, event_type: str) -> int:
    return len(kernel.audit.events_of_type(event_type))


def test_a_successful_operation_is_recorded_once_and_returns_its_result(
    kernel: Kernel, admin: tuple[str, str]
) -> None:
    token = _token(kernel)
    before = _count(kernel, "operation.executed")
    assert kernel.security.guard.run(token, READ, lambda: 42) == 42
    assert _count(kernel, "operation.executed") == before + 1
    assert _count(kernel, "operation.failed") == 0


def test_a_failing_operation_raises_its_own_error_and_is_recorded_as_failed(
    kernel: Kernel, admin: tuple[str, str]
) -> None:
    token = _token(kernel)

    def fails() -> None:
        raise ValidationError("contenido con una ruta C:\\datos\\privado")

    with pytest.raises(ValidationError, match="ruta"):
        kernel.security.guard.run(token, READ, fails)
    failed = kernel.audit.events_of_type("operation.failed")
    assert len(failed) == 1
    payload = failed[-1]["payload"]
    assert payload == {
        "username": ADMIN_USER,
        "permission": READ,
        "critical": False,
        "error": "ValidationError",
    }
    # El texto del error no llega a la auditoría: puede llevar rutas o datos internos.
    assert "privado" not in str(payload)


def test_a_failed_operation_is_not_recorded_as_executed(
    kernel: Kernel, admin: tuple[str, str]
) -> None:
    token = _token(kernel)
    before = _count(kernel, "operation.executed")
    with pytest.raises(RuntimeError):
        kernel.security.guard.run(token, READ, _raise_runtime)
    assert _count(kernel, "operation.executed") == before


def _raise_runtime() -> None:
    raise RuntimeError("fallo interno de prueba")


def test_an_audit_error_does_not_hide_the_result_of_a_successful_operation(
    kernel: Kernel,
    admin: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    token = _token(kernel)
    original = AuditLog.record

    def failing_record(
        self: AuditLog,
        event_type: str,
        payload: object,
        connection: object = None,
        **kwargs: object,
    ) -> None:
        if event_type == "operation.executed":
            raise ValidationError("registro no disponible")
        original(self, event_type, payload, connection, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(AuditLog, "record", failing_record)
    with caplog.at_level(logging.ERROR, logger="natxajo_auditor.security.guard"):
        assert kernel.security.guard.run(token, READ, lambda: "resultado") == "resultado"
    assert "No se pudo registrar la ejecución" in caplog.text


def test_an_audit_error_does_not_replace_the_original_failure(
    kernel: Kernel,
    admin: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    token = _token(kernel)
    original = AuditLog.record
    error = RuntimeError("fallo original")

    def failing_record(
        self: AuditLog,
        event_type: str,
        payload: object,
        connection: object = None,
        **kwargs: object,
    ) -> None:
        if event_type == "operation.failed":
            raise ValidationError("registro no disponible")
        original(self, event_type, payload, connection, **kwargs)  # type: ignore[arg-type]

    def fails() -> None:
        raise error

    monkeypatch.setattr(AuditLog, "record", failing_record)
    with (
        caplog.at_level(logging.ERROR, logger="natxajo_auditor.security.guard"),
        pytest.raises(RuntimeError) as caught,
    ):
        kernel.security.guard.run(token, READ, fails)
    assert caught.value is error
    assert "No se pudo registrar el fallo" in caplog.text


def test_a_failure_seen_by_an_inner_operation_is_recorded_only_once(
    kernel: Kernel, admin: tuple[str, str]
) -> None:
    token = _token(kernel)
    guard = kernel.security.guard

    def inner() -> None:
        guard.run(token, READ, _raise_runtime)

    before = _count(kernel, "operation.failed")
    with pytest.raises(RuntimeError):
        guard.run(token, READ, inner)
    assert _count(kernel, "operation.failed") == before + 1


def test_a_denial_inside_an_operation_is_recorded_once_and_not_as_failure(
    kernel: Kernel, admin: tuple[str, str]
) -> None:
    kernel.security.companies.create("acme", "Acme S.A.")
    kernel.security.create_account(AUDITOR, PASSWORD, ["auditor"], "acme")
    token = kernel.security.login(AUDITOR, PASSWORD)
    guard = kernel.security.guard
    denied_before = _count(kernel, "operation.denied")
    failed_before = _count(kernel, "operation.failed")

    def tries_another_company() -> None:
        # Una cuenta de acme no puede actuar sobre la plataforma: el guardián lo deniega dentro.
        guard.check_scope(token, "plataforma", READ)

    with pytest.raises(AuthorizationError):
        guard.run(token, READ, tries_another_company, company_id="acme")
    assert _count(kernel, "operation.denied") == denied_before + 1
    assert _count(kernel, "operation.failed") == failed_before


def test_a_plain_denial_is_recorded_as_denied_only(kernel: Kernel, admin: tuple[str, str]) -> None:
    kernel.security.companies.create("acme", "Acme S.A.")
    kernel.security.create_account(AUDITOR, PASSWORD, ["auditor"], "acme")
    token = kernel.security.login(AUDITOR, PASSWORD)
    failed_before = _count(kernel, "operation.failed")
    denied_before = _count(kernel, "operation.denied")
    # Sin empresa indicada la operación es de plataforma: la cuenta de acme no la ejecuta.
    with pytest.raises(AuthorizationError):
        kernel.security.guard.run(token, READ, lambda: None)
    assert _count(kernel, "operation.denied") == denied_before + 1
    assert _count(kernel, "operation.failed") == failed_before
