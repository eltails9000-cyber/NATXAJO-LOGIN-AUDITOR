# NATXAJO-LOGIN-AUDITOR
Professional Windows authentication security auditing tool built with Python and PowerShell. Includes login form analysis, controlled authentication testing, password policy evaluation, rate-limit auditing and security reports.

> La descripción anterior es el alcance objetivo del proyecto. Hoy están implementados el núcleo, la configuración, las versiones, los módulos y la verificación de plugins; las funciones de auditoría todavía no existen (ver `docs/IMPLEMENTATION_STATUS.md`).

Solo debe usarse sobre sistemas propios o con autorización verificable por escrito. No incluye fuerza bruta, credential stuffing, adivinación de contraseñas, evasión de controles ni recolección de credenciales reales. Ver `docs/seguridad.md`.

## Requisitos

- Python 3.11 o posterior.
- Windows 10 u 11 para el lanzador `launcher.ps1`. El resto funciona en cualquier sistema con Python 3.11+.

## Ejecución

Desde la carpeta del proyecto:

```bash
python main.py            # menú interactivo
python main.py --version  # muestra la versión y sale
```

En Windows también puede usarse `.\launcher.ps1`, que busca un Python 3.11 o posterior.

Los datos de ejecución (`config/`, `storage/`) se crean en la carpeta del proyecto la primera vez y no se versionan.

## Pruebas

```bash
python -m pip install -e .[dev]
python -m pytest
python -m ruff check .
python -m mypy
```

## Documentación

- `docs/diagnostico-inicial.md`: estado del repositorio al reconstruirlo y decisiones de estructura.
- `docs/arquitectura.md`: capas, ciclo de vida, decisiones (D1 a D8) y ubicación de los datos.
- `docs/seguridad.md`: límites de uso y qué está y qué no está implementado.
- `docs/IMPLEMENTATION_STATUS.md`: estado verificado de cada fase.
- `CHANGELOG.md`: historial de cambios.

## Estado

Implementado: núcleo con ciclo de vida, configuración validada con historial y copias restaurables
con autorización, base SQLite con migraciones, auditoría, manifiestos de versión con carga manual,
cambio y reversión, módulos declarativos con dependencias habilitables, plugins firmados (editores,
catálogo local, revisión y habilitación con dependencias), y terminal interactiva.

Pendiente: ejecución de módulos y plugins, gestión de plugins en la terminal, RBAC, automatización, motor de auditoría, interfaz de
escritorio, informes y mantenimiento. No se declaran como disponibles hasta que tengan pruebas.
