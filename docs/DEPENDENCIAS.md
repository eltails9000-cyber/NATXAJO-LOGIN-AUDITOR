# Dependencias y versiones probadas

## Ejecución

El proyecto no tiene dependencias de ejecución. Usa solo la biblioteca estándar de Python 3.11 o
posterior (`requires-python = ">=3.11"`).

## Desarrollo: rangos declarados

Los rangos están en `pyproject.toml`, en `[project.optional-dependencies]`.

| Herramienta | Rango declarado | Versión probada |
|---|---|---|
| pytest | `>=9.1,<10` | 9.1.1 |
| ruff | `>=0.16,<0.17` | 0.16.9 |
| mypy | `>=2.3,<3` | 2.3.1 |

Criterio: el rango incluye solo versiones que se han ejecutado en este repositorio. Los límites
inferiores anteriores (pytest 8.0, ruff 0.6 y mypy 1.11) se retiraron porque no se han probado. Un
rango se amplía así: se ejecuta la suite con la nueva versión, se actualiza `requirements-dev.lock`
y se comprueba `tests/test_dependencias.py`.

## Bloqueo: `requirements-dev.lock`

El fichero fija la versión exacta de las herramientas y de sus dependencias: doce paquetes de Python
más `ruff`, que es un binario sin dependencias. Se calculó desde los metadatos instalados, con los
marcadores evaluados para Python 3.11 en Linux y en Windows. `colorama` solo se instala en Windows.

Se usa como restricciones de instalación:

```bash
python -m pip install -c requirements-dev.lock -e ".[dev]"
```

**Limitación pendiente:** el bloqueo no fija hashes de los artefactos. Un bloqueo con hashes exige
generarlo con acceso al índice de paquetes (`pip-compile --generate-hashes` o `uv lock`). El entorno
de desarrollo no tenía acceso al índice, así que no se pudo generar.

`tests/test_dependencias.py` comprueba que el bloqueo fija cada herramienta dentro de su rango, que
cada entrada es una versión exacta y que el proyecto no declara dependencias de ejecución.

## Verificación realizada

| Comprobación | Entorno | Resultado |
|---|---|---|
| Suite completa, 302 casos | Python 3.13.18, Linux | Todos pasan. |
| Suite completa, 302 casos | Python 3.11.18, Linux, entorno virtual limpio | Todos pasan. Sin acceso al índice, pytest, pluggy, iniconfig, pygments y packaging se tomaron del entorno 3.13 (versiones 9.1.1, 1.6.0, 2.3.0, 2.21.0 y 26.3). |
| Instalación del proyecto en entorno virtual limpio | Python 3.11.18, sin red (`--no-index --no-deps --no-build-isolation`) | Se construye, se instala con cero dependencias e importa (versión 0.1.0). |
| `ruff check`, `ruff format --check` | ruff 0.16.9 | Sin errores. |
| `mypy` en modo estricto | mypy 2.3.1, `python_version = "3.11"` | Sin errores en 61 archivos. |

No está verificado:

- La instalación con `requirements-dev.lock` desde el índice, en un entorno vacío. Requiere red.
- Windows 10 y 11. Ver `docs/PRUEBAS_WINDOWS.md`.
- Las herramientas no se han ejecutado con Python 3.11 como intérprete. ruff y mypy se ejecutaron
  desde 3.13 con sus objetivos `py311`, que es lo que comprueban.

## Reproducir la instalación limpia

Con acceso al índice:

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows; en Linux: source .venv/bin/activate
python -m pip install -c requirements-dev.lock -e ".[dev]"
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy
```
