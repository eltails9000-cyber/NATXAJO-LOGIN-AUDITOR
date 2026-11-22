"""Dependencias (P-17): los rangos declarados, el bloqueo y la política de ejecución son coherentes.

Estas pruebas no instalan nada. Comprueban que el bloqueo cumple los rangos del proyecto y que el
proyecto no tiene dependencias de ejecución.
"""

import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]


def _project() -> dict[str, object]:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _project_table() -> dict[str, object]:
    table = _project()["project"]
    assert isinstance(table, dict)
    return table


def _development_requirements() -> list[Requirement]:
    extras = _project_table()["optional-dependencies"]
    assert isinstance(extras, dict)
    values = extras["dev"]
    assert isinstance(values, list)
    return [Requirement(str(value)) for value in values]


def _lock_pins() -> dict[str, Version]:
    pins: dict[str, Version] = {}
    for raw in (ROOT / "requirements-dev.lock").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        specifiers = list(requirement.specifier)
        assert len(specifiers) == 1 and specifiers[0].operator == "==", line
        name = canonicalize_name(requirement.name)
        assert name not in pins, f"entrada duplicada en el bloqueo: {name}"
        pins[name] = Version(specifiers[0].version)
    return pins


def test_the_project_has_no_runtime_dependencies() -> None:
    assert _project_table()["dependencies"] == []


def test_the_minimum_python_is_311() -> None:
    assert _project_table()["requires-python"] == ">=3.11"


def test_every_development_requirement_has_an_upper_bound() -> None:
    for requirement in _development_requirements():
        operators = {specifier.operator for specifier in requirement.specifier}
        assert "<" in operators or "<=" in operators, requirement


def test_the_lock_pins_every_declared_development_tool_within_its_range() -> None:
    pins = _lock_pins()
    for requirement in _development_requirements():
        name = canonicalize_name(requirement.name)
        assert name in pins, f"el bloqueo no fija {name}"
        assert requirement.specifier.contains(pins[name]), f"{name} {pins[name]} fuera del rango"


def test_the_lock_only_pins_exact_versions() -> None:
    # _lock_pins falla si una línea no es exactamente una restricción ==, o si repite un paquete.
    assert _lock_pins()
