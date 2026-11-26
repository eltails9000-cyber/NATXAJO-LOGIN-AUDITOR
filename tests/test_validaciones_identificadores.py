"""Validación de identificadores: un salto de línea final no puede pasar por válido.

Con `re.match` y un patrón terminado en `$`, la cadena "acme\\n" se acepta: `$` coincide antes del
salto final. Los validadores usan `fullmatch`, que exige que el patrón cubra la cadena entera.
"""

from __future__ import annotations

import re

import pytest

from natxajo_auditor.auditing.results import _SHA256
from natxajo_auditor.core.events import COMPANY_ID, build_event
from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.core.permissions import _SEGMENT, parse_permission
from natxajo_auditor.core.utilities import utc_now
from natxajo_auditor.core.validation import (
    IDENTIFIER,
    KERNEL_PATTERN,
    KEY_ID,
    SEMVER,
    kernel_matches,
    require_identifier,
    require_kernel_pattern,
    require_semver,
)
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.plugins.repository import _SHA256_HEX
from natxajo_auditor.security.accounts import USERNAME

# --- Patrones: ninguno acepta un salto de línea final --------------------------------------------

PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("events.COMPANY_ID", COMPANY_ID, "acme"),
    ("accounts.USERNAME", USERNAME, "auditor_acme"),
    ("validation.IDENTIFIER", IDENTIFIER, "modulo_ejemplo"),
    ("validation.SEMVER", SEMVER, "1.2.3"),
    ("validation.KERNEL_PATTERN", KERNEL_PATTERN, "0.1.x"),
    ("validation.KEY_ID", KEY_ID, "editor.acme-1"),
    ("permissions._SEGMENT", _SEGMENT, "cuenta"),
    ("results._SHA256", _SHA256, "a" * 64),
    ("repository._SHA256_HEX", _SHA256_HEX, "b" * 64),
]


@pytest.mark.parametrize(("label", "pattern", "valid"), PATTERNS, ids=[p[0] for p in PATTERNS])
def test_the_valid_value_is_accepted_and_a_trailing_newline_is_not(
    label: str, pattern: re.Pattern[str], valid: str
) -> None:
    assert pattern.fullmatch(valid) is not None
    assert pattern.fullmatch(valid + "\n") is None, label
    assert pattern.fullmatch("\n" + valid) is None, label


@pytest.mark.parametrize(("label", "pattern", "valid"), PATTERNS, ids=[p[0] for p in PATTERNS])
def test_a_value_with_extra_text_inside_is_rejected(
    label: str, pattern: re.Pattern[str], valid: str
) -> None:
    assert pattern.fullmatch(valid + " ") is None, label
    assert pattern.fullmatch(" " + valid) is None, label


# --- Validadores públicos ------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["modulo_ok", "a_b_c", "x" * 40])
def test_identifiers_accept_the_documented_shape(value: str) -> None:
    assert require_identifier(value, "id", "prueba") == value


@pytest.mark.parametrize(
    "value",
    ["", "ab", "Modulo", "modulo\n", " modulo", "modulo ", "1modulo", "x" * 41, "mo-dulo"],
)
def test_identifiers_reject_invalid_values_including_a_final_newline(value: str) -> None:
    with pytest.raises(ValidationError):
        require_identifier(value, "id", "prueba")


@pytest.mark.parametrize("value", ["1.0.0", "10.20.30"])
def test_semver_accepts_valid_versions(value: str) -> None:
    assert require_semver(value, "version", "prueba") == value


@pytest.mark.parametrize("value", ["1.0.0\n", "1.0", "01.0.0", "1.0.0-beta", "v1.0.0"])
def test_semver_rejects_invalid_versions(value: str) -> None:
    with pytest.raises(ValidationError):
        require_semver(value, "version", "prueba")


def test_kernel_patterns_reject_a_trailing_newline() -> None:
    assert require_kernel_pattern("0.1.x", "nucleo", "prueba") == "0.1.x"
    with pytest.raises(ValidationError):
        require_kernel_pattern("0.1.x\n", "nucleo", "prueba")
    assert kernel_matches("0.1.x", "0.1.4")
    with pytest.raises(ValidationError):
        kernel_matches("0.1.x", "0.1.4\n")


def test_permissions_reject_a_segment_with_a_trailing_newline() -> None:
    assert str(parse_permission("seguridad:nucleo:cuenta:administrar", source="prueba"))
    with pytest.raises(ValidationError):
        parse_permission("seguridad:nucleo:cuenta\n:administrar", source="prueba")


def test_events_reject_a_company_identifier_with_a_trailing_newline() -> None:
    occurred = utc_now()
    event = build_event(
        "kernel.stopped", {}, event_id="e1", occurred_at=occurred, company_id="acme"
    )
    assert event.company_id == "acme"
    with pytest.raises(ValidationError):
        build_event("kernel.stopped", {}, event_id="e2", occurred_at=occurred, company_id="acme\n")


def test_accounts_reject_a_username_with_a_trailing_newline(kernel: Kernel) -> None:
    accounts = kernel.security.accounts
    with pytest.raises(ValidationError):
        accounts.prepare_new("auditor_ok\n", "contraseña-de-prueba-7", ["auditor"], "plataforma")


def test_companies_reject_an_identifier_with_a_trailing_newline(kernel: Kernel) -> None:
    with pytest.raises(ValidationError):
        kernel.security.companies.create("acme\n", "Acme S.A.")
    assert kernel.security.companies.create("acme", "Acme S.A.").company_id == "acme"


def test_key_identifiers_reject_a_trailing_newline() -> None:
    assert KEY_ID.fullmatch("editor-acme") is not None
    assert KEY_ID.fullmatch("editor-acme\n") is None
