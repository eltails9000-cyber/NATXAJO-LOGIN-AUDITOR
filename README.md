# NATXAJO-LOGIN-AUDITOR
Professional Windows authentication security auditing tool built with Python and PowerShell. Includes login form analysis, controlled authentication testing, password policy evaluation, rate-limit auditing and security reports.

> La descripción anterior es el alcance objetivo del proyecto. Hoy están implementados el núcleo, la configuración, las versiones, los módulos, la verificación de plugins, el control de acceso, un motor de auditoría que evalúa configuraciones declaradas sin conexión, los informes y el mantenimiento básico. No hay pruebas activas contra sistemas en ejecución (ver `docs/IMPLEMENTATION_STATUS.md`).

Solo debe usarse sobre sistemas propios o con autorización verificable por escrito. No incluye fuerza bruta, credential stuffing, adivinación de contraseñas, evasión de controles ni recolección de credenciales reales. Ver `docs/seguridad.md`.

## Requisitos

- Python 3.11 o posterior.
- Windows 10 u 11 para el lanzador `launcher.ps1`. El resto funciona en cualquier sistema con Python 3.11+.

## Ejecución

Desde la carpeta del proyecto:

```bash
python main.py            # menú interactivo
python main.py --gui      # interfaz gráfica en el navegador (solo 127.0.0.1)
python main.py --version  # muestra la versión y sale
```

La interfaz gráfica usa el navegador del equipo y se detiene con Ctrl+C en la consola. Su
funcionamiento y sus límites están en `docs/INTERFAZ_GRAFICA.md`.

En Windows también puede usarse `.\launcher.ps1`, que busca un Python 3.11 o posterior. Con la
política de ejecución por defecto de Windows, el script no se ejecuta; use:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\launcher.ps1
```

El lanzador no se ha ejecutado todavía en Windows: su texto tiene pruebas estáticas, pero la
ejecución real requiere un equipo Windows. El procedimiento de prueba está en
`docs/PRUEBAS_WINDOWS.md`.

Los datos de ejecución (`config/`, `storage/`) se crean en la carpeta del proyecto la primera vez y no se versionan.

La primera vez que se abre la terminal, con la base vacía, se muestra un código de instalación de un solo uso y se crea la cuenta de administrador de la plataforma. Después, cada uso requiere iniciar sesión.

## Pruebas

```bash
python -m pip install -c requirements-dev.lock -e ".[dev]"
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m mypy
```

Versiones probadas, rangos y limitaciones del bloqueo: `docs/DEPENDENCIAS.md`.

## Documentación

- `docs/diagnostico-inicial.md`: estado del repositorio al reconstruirlo y decisiones de estructura.
- `docs/arquitectura.md`: capas, ciclo de vida, decisiones (D1 a D12) y ubicación de los datos.
- `docs/MIGRACION_ETAPA_2.md`: plan y resultados de la migración a multiempresa, instalador y bus de eventos.
- `docs/seguridad.md`: límites de uso, controles implementados y lo que no está implementado.
- `docs/DEPENDENCIAS.md`: rangos de desarrollo, bloqueo, versiones probadas y lo no verificado.
- `docs/IMPLEMENTATION_STATUS.md`: estado verificado de cada fase.
- `docs/AUDITORIA_MOTOR.md`: motor de auditoría, esquema del documento, reglas y perfiles.
- `docs/INFORMES.md`: formatos de informe, exportación, verificación y eventos.
- `docs/MANTENIMIENTO.md`: diagnóstico, limpieza de temporales y recuperación ante errores.
- `docs/MATRIZ_ETAPA_4.md`: funcionalidades, archivos y pruebas de la etapa 4.
- `docs/PLUGINS_CICLO.md`: cuarentena, actualización y reversión de plugins, permisos, reglas y límites.
- `docs/CLAUDE_ARCHITECTURE_AUDIT.md`: auditoría de arquitectura y plan de corrección por etapas.
- `CHANGELOG.md`: historial de cambios.

## Estado

Implementado: núcleo con ciclo de vida, configuración validada con historial y copias restaurables con autorización, base SQLite con migraciones, auditoría, manifiestos de versión con carga manual, cambio y reversión, módulos declarativos con dependencias habilitables, plugins firmados (editores, catálogo local, revisión, habilitación con dependencias, cuarentena, actualización y reversión), cuentas con roles y sesiones, permisos temporales, guardián de operaciones críticas y terminal interactiva.

Multiempresa: las cuentas pertenecen a una empresa y el ámbito se comprueba en el guardián; faltan aplicaciones y entornos. Instalador con código de un solo uso y bus de eventos con auditoría.

Etapa 4: motor de auditoría sin conexión (17 reglas, perfiles y evaluaciones inmutables), informes JSON, CSV, HTML y TXT con verificación, diagnóstico y limpieza de temporales, y terminal con las opciones 20 a 33 (evaluaciones, informes, mantenimiento, reglas y, para plugins, estado, cuarentena, actualización y reversión).

Pendiente: ejecución de módulos y plugins, instalación y habilitación de plugins desde la terminal, gestión de permisos desde la terminal, restauración de copias desde la terminal, automatización, pruebas activas de auditoría e interfaz de escritorio. No se declaran como disponibles hasta que tengan pruebas.
