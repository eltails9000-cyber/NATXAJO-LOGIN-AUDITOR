# NATXAJO-LOGIN-AUDITOR
Professional Windows authentication security auditing tool built with Python and PowerShell. Includes login form analysis, controlled authentication testing, password policy evaluation, rate-limit auditing and security reports.

> La descripción anterior es el alcance objetivo del proyecto. Hoy están implementados el núcleo, la configuración, las versiones, los módulos, la verificación de plugins y el control de acceso; las funciones de auditoría todavía no existen (ver `docs/IMPLEMENTATION_STATUS.md`).

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

La primera vez que se abre la terminal, con la base vacía, se muestra un código de instalación de un solo uso y se crea la cuenta de administrador de la plataforma. Después, cada uso requiere iniciar sesión.

## Pruebas

```bash
python -m pip install -e .[dev]
python -m pytest
python -m ruff check .
python -m mypy
```

## Documentación

- `docs/diagnostico-inicial.md`: estado del repositorio al reconstruirlo y decisiones de estructura.
- `docs/arquitectura.md`: capas, ciclo de vida, decisiones (D1 a D12) y ubicación de los datos.
- `docs/MIGRACION_ETAPA_2.md`: plan y resultados de la migración a multiempresa, instalador y bus de eventos.
- `docs/seguridad.md`: límites de uso, controles implementados y lo que no está implementado.
- `docs/IMPLEMENTATION_STATUS.md`: estado verificado de cada fase.
- `docs/CLAUDE_ARCHITECTURE_AUDIT.md`: auditoría de arquitectura y plan de corrección por etapas.
- `CHANGELOG.md`: historial de cambios.

## Estado

Implementado: núcleo con ciclo de vida, configuración validada con historial y copias restaurables con autorización, base SQLite con migraciones, auditoría, manifiestos de versión con carga manual, cambio y reversión, módulos declarativos con dependencias habilitables, plugins firmados (editores, catálogo local, revisión y habilitación con dependencias), cuentas con roles y sesiones, permisos temporales, guardián de operaciones críticas y terminal interactiva.

Multiempresa: las cuentas pertenecen a una empresa y el ámbito se comprueba en el guardián; faltan aplicaciones y entornos. Instalador con código de un solo uso y bus de eventos con auditoría.

Pendiente: ejecución de módulos y plugins, gestión de plugins y de permisos desde la terminal, automatización, motor de auditoría, interfaz de escritorio, informes y mantenimiento. No se declaran como disponibles hasta que tengan pruebas.
