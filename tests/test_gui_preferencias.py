"""Preferencias visuales de la interfaz: validación estricta, lectura tolerante y guardado atómico."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from natxajo_auditor.core.exceptions import ValidationError
from natxajo_auditor.interfaces.gui import preferences
from natxajo_auditor.interfaces.gui.preferences import Preferences, from_mapping, load, save


def test_defaults_are_the_documented_ones() -> None:
    base = Preferences()
    assert base.tema == "oscuro"
    assert base.densidad == "comoda"
    assert base.movimiento == "normal"
    assert base.pagina_inicio == "panel"
    assert base.actualizacion_segundos == 0
    assert base.filas_por_pagina == 25
    assert base.notificaciones is True


def test_valid_values_are_accepted() -> None:
    prefs = from_mapping(
        {
            "tema": "claro",
            "densidad": "compacta",
            "movimiento": "reducido",
            "pagina_inicio": "auditoria",
            "actualizacion_segundos": 60,
            "filas_por_pagina": 100,
            "notificaciones": False,
        }
    )
    assert prefs.tema == "claro"
    assert prefs.actualizacion_segundos == 60
    assert prefs.notificaciones is False


@pytest.mark.parametrize(
    "data",
    [
        {"tema": "rojo"},
        {"densidad": "enorme"},
        {"pagina_inicio": "inexistente"},
        {"actualizacion_segundos": 45},
        {"actualizacion_segundos": True},
        {"filas_por_pagina": 7},
        {"notificaciones": "sí"},
        {"tema": 1},
    ],
)
def test_out_of_range_values_are_rejected(data: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        from_mapping(data)


def test_unknown_keys_are_rejected_instead_of_ignored() -> None:
    # Un error tipográfico no debe pasar en silencio.
    with pytest.raises(ValidationError, match="desconocida"):
        from_mapping({"temma": "claro"})


def test_missing_file_gives_defaults_without_warning(tmp_path: Path) -> None:
    result = load(tmp_path / preferences.FILE_NAME)
    assert result.preferences == Preferences()
    assert result.warning is None


def test_unreadable_file_gives_defaults_and_a_warning(tmp_path: Path) -> None:
    path = tmp_path / preferences.FILE_NAME
    path.write_text("{ no es json", encoding="utf-8")
    result = load(path)
    assert result.preferences == Preferences()
    assert result.warning is not None and "ignoradas" in result.warning


def test_file_with_invalid_values_gives_defaults_and_a_warning(tmp_path: Path) -> None:
    path = tmp_path / preferences.FILE_NAME
    path.write_text(json.dumps({"tema": "neón"}), encoding="utf-8")
    result = load(path)
    assert result.preferences == Preferences()
    assert result.warning is not None


def test_oversized_file_is_not_read(tmp_path: Path) -> None:
    path = tmp_path / preferences.FILE_NAME
    path.write_text(" " * (preferences.MAX_FILE_BYTES + 1), encoding="utf-8")
    result = load(path)
    assert result.preferences == Preferences()
    assert result.warning is not None


def test_save_round_trips_and_leaves_no_temporary_file(tmp_path: Path) -> None:
    path = tmp_path / "config" / preferences.FILE_NAME
    saved = from_mapping({"tema": "claro", "actualizacion_segundos": 300})
    save(path, saved)
    assert load(path).preferences == saved
    assert not path.with_name(path.name + ".tmp").exists()


def test_save_replaces_the_previous_content_completely(tmp_path: Path) -> None:
    path = tmp_path / preferences.FILE_NAME
    save(path, from_mapping({"tema": "claro"}))
    save(path, from_mapping({"tema": "oscuro"}))
    assert json.loads(path.read_text(encoding="utf-8"))["tema"] == "oscuro"
