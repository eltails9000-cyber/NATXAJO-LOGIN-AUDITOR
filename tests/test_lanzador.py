"""Pruebas del lanzador launcher.ps1.

Windows no está disponible en este entorno, así que el lanzador NO se ejecuta aquí. Estas pruebas
comprueban el texto del script: codificación, detección de Python, alias de la Microsoft Store,
propagación de códigos de salida, rutas con espacios y ausencia de cambios en la política de
ejecución. Si PowerShell está instalado, además se comprueba que el analizador acepte el script.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

LAUNCHER = Path(__file__).resolve().parents[1] / "launcher.ps1"
BOM = b"\xef\xbb\xbf"


def _text() -> str:
    return LAUNCHER.read_bytes().decode("utf-8-sig")


def test_the_script_is_saved_with_a_utf8_bom_for_windows_powershell() -> None:
    # Windows PowerShell 5.1 lee los .ps1 sin BOM como ANSI y estropea los acentos.
    assert LAUNCHER.read_bytes().startswith(BOM)


def test_the_script_requires_python_311_or_later() -> None:
    assert "sys.version_info >= (3, 11)" in _text()


def test_store_aliases_are_skipped_and_every_candidate_is_run_before_use() -> None:
    text = _text()
    assert "WindowsApps" in text
    assert "-CommandType Application" in text
    assert "if ($LASTEXITCODE -ne 0) { continue }" in text


def test_candidates_cover_the_py_launcher_and_both_python_names() -> None:
    text = _text()
    assert '"-3.11"' in text
    assert '"-3"' in text
    assert 'Exe = "python"' in text
    assert 'Exe = "python3"' in text


def test_arguments_are_forwarded_and_the_exit_code_propagates() -> None:
    text = _text()
    assert "$Entry @args" in text
    assert text.rstrip().endswith("exit $LASTEXITCODE")


def test_paths_with_spaces_are_handled_as_literal_paths() -> None:
    text = _text()
    assert "Set-Location -LiteralPath $ProjectRoot" in text
    assert "Test-Path -LiteralPath $Entry" in text
    assert "Join-Path $ProjectRoot" in text


def test_a_missing_interpreter_is_a_clear_message_with_exit_code_one() -> None:
    text = _text()
    assert "no se encontró Python 3.11 o posterior" in text
    assert "throw" not in text
    assert "exit 1" in text


def test_a_missing_main_py_is_reported_before_running_anything() -> None:
    text = _text()
    assert "no se encuentra main.py" in text
    assert text.index("no se encuentra main.py") < text.index("& $Interpreter.Exe")


def test_the_script_never_changes_the_execution_policy() -> None:
    lowered = _text().lower()
    assert "set-executionpolicy" not in lowered
    assert "bypass" not in lowered
    assert "unrestricted" not in lowered


def test_the_script_parses_when_powershell_is_available() -> None:
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("PowerShell no está disponible: el lanzador no se analizó ni se ejecutó")
    command = (
        "$tokens = $null; $errors = $null; "
        "[void][System.Management.Automation.Language.Parser]::ParseFile("
        "$env:LAUNCHER_PATH, [ref]$tokens, [ref]$errors); "
        "if ($errors) { $errors | ForEach-Object { $_.Message }; exit 1 }"
    )
    env = {**os.environ, "LAUNCHER_PATH": str(LAUNCHER)}
    result = subprocess.run(
        [shell, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
