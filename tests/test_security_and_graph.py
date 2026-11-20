"""Permisos, grafo de dependencias genérico y validadores compartidos."""

import pytest

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.graph import dependents_of, resolve_load_order
from natxajo_auditor.core.validation import (
    require_identifier,
    require_kernel_pattern,
    require_semver,
    require_string_list,
)
from natxajo_auditor.security.permissions import (
    Permission,
    covers,
    parse_permission,
    validate_declared,
)


def test_parse_exact_permission() -> None:
    permission = parse_permission("auditoria:nucleo:evento:leer")
    assert permission == Permission("auditoria", "nucleo", "evento", "leer")
    assert str(permission) == "auditoria:nucleo:evento:leer"
    assert permission.is_exact()


@pytest.mark.parametrize(
    "code",
    [
        "auditoria.leer",
        "auditoria:nucleo:leer",
        "desconocido:nucleo:evento:leer",
        "auditoria:nucleo:evento:borrar",
        "auditoria:Nucleo:evento:leer",
        "auditoria:nucleo:evento:*",
    ],
)
def test_invalid_permission_codes_are_rejected(code: str) -> None:
    with pytest.raises(ValidationError):
        parse_permission(code)


def test_wildcards_are_allowed_only_in_grants() -> None:
    grant = parse_permission("auditoria:*:*:leer", allow_wildcards=True)
    assert not grant.is_exact()


def test_declarations_reject_wildcards() -> None:
    with pytest.raises(ValidationError, match="no admite comodines"):
        validate_declared(["auditoria:*:*:leer"], "prueba")


def test_declared_list_rejects_duplicates_and_non_lists() -> None:
    with pytest.raises(ValidationError, match="repetidos"):
        validate_declared(
            ["auditoria:nucleo:evento:leer", "auditoria:nucleo:evento:leer"], "prueba"
        )
    with pytest.raises(ValidationError, match="lista de textos"):
        validate_declared("auditoria:nucleo:evento:leer", "prueba")


def test_grant_covers_matching_permissions_only() -> None:
    grant = parse_permission("auditoria:*:*:leer", allow_wildcards=True)
    assert covers(grant, parse_permission("auditoria:nucleo:evento:leer"))
    assert not covers(grant, parse_permission("auditoria:nucleo:evento:escribir"))


def test_concrete_grant_does_not_cover_wildcard_request() -> None:
    grant = parse_permission("auditoria:nucleo:evento:leer")
    assert not covers(grant, parse_permission("auditoria:*:*:leer", allow_wildcards=True))


def test_load_order_puts_dependencies_first() -> None:
    requires = {"a": ("b",), "b": ("c",), "c": ()}
    assert resolve_load_order(lambda item: requires.get(item), "a", noun="elemento") == [
        "c",
        "b",
        "a",
    ]


def test_missing_dependency_names_its_requester() -> None:
    requires = {"a": ("falta",)}
    with pytest.raises(ValidationError, match="elemento no instalado: falta .requerido por a."):
        resolve_load_order(lambda item: requires.get(item), "a", noun="elemento")


def test_dependency_cycle_is_detected() -> None:
    requires = {"a": ("b",), "b": ("a",)}
    with pytest.raises(ValidationError, match="ciclo de dependencias"):
        resolve_load_order(lambda item: requires.get(item), "a")


def test_dependents_are_sorted() -> None:
    assert dependents_of({"z": ("a",), "m": ("a",), "x": ()}, "a") == ["m", "z"]


def test_shared_validators_accept_and_reject() -> None:
    assert require_identifier("modulo_ok", "id", "prueba") == "modulo_ok"
    with pytest.raises(ValidationError):
        require_identifier("No Valido", "id", "prueba")
    assert require_semver("1.2.3", "version", "prueba") == "1.2.3"
    with pytest.raises(ValidationError):
        require_semver("1.2", "version", "prueba")
    assert require_kernel_pattern("0.1.x", "compatible", "prueba") == "0.1.x"
    with pytest.raises(ValidationError):
        require_kernel_pattern("0.1", "compatible", "prueba")
    assert require_string_list(None, "dependencies", "prueba") == ()
    with pytest.raises(ValidationError, match="repetidos"):
        require_string_list(["a", "a"], "dependencies", "prueba")
