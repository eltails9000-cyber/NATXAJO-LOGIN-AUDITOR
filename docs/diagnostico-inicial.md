# Diagnóstico inicial (Fase 1)

## Estado del repositorio al empezar

El commit inicial contenía solo `.gitignore`, `LICENSE` y `README.md`. Commits posteriores
añadieron código que después se eliminó para reconstruir la plataforma desde una base limpia.
El código anterior sigue en el historial (commit `3868286`) y puede consultarse allí.

## Problemas encontrados en el código anterior

| Hallazgo | Impacto | Resolución |
|---|---|---|
| `python main.py` fallaba en una copia limpia: el paquete no estaba en `sys.path`. | El punto de entrada no funcionaba sin instalar. | `main.py` añade `src/` al path. Prueba en `tests/test_entry_point.py`. |
| `StorageManager.integrity()` solo comprobaba que las rutas existieran. Devolvía `healthy` aunque las copias hubieran sido borradas o alteradas. | Verificación simulada: podía dar falsa seguridad. | Verificación SHA-256 con manifiesto en cada copia. Restauración que comprueba el hash antes de copiar. |
| Una prueba creaba carpetas en el directorio de trabajo. | Ensuciaba el repositorio al ejecutar pruebas. | Las pruebas usan `tmp_path`. |
| La versión del proyecto no coincidía: `pyproject.toml` decía 0.1.0, `CHANGELOG.md` decía 0.2.0 y el registro solo conocía 0.1.0 (codificado a mano). | Información contradictoria sobre qué versión existe. | Un único origen: `__version__` y `versions/<versión>/manifest.json`. |
| Las snapshots de configuración usaban precisión de segundos en el nombre. | Dos cambios en el mismo segundo podían sobrescribir el historial. | Marcas con microsegundos. |
| La tabla `audit_events` existía pero nada escribía en ella. Varias piezas (bus de comandos, `HealthChecker`) no se usaban. | Código muerto y falsa sensación de funcionalidad. | Eliminado. La auditoría ahora se escribe al activar versiones. |
| `.env.example` documentaba variables (`APP_ENV`, `DATA_DIR`, etc.) que solo servían para cambiar rutas, y el resto del código no las usaba. | Configuración por entorno sin uso real y con dos fuentes de verdad (env y `app.json`). | Las rutas son fijas dentro del proyecto. No se incluye `.env.example` hasta que haya variables que documentar. |

## Estructura adoptada

Se implementan solo los subsistemas con responsabilidad real hoy. Los demás nombres del
documento maestro quedan pendientes en `docs/roadmap.md`; no se crean carpetas vacías.

```
src/natxajo_auditor/
  core/            excepciones, utilidades (hash, escritura atómica, marcas de tiempo)
  kernel/          núcleo, ciclo de vida, contenedor de servicios, bus de eventos, contexto
  configuration/   esquema estricto, gestor con historial y copias
  storage/         base de datos SQLite, migraciones, auditoría, copias con manifiesto
  versioning/      canales, manifiestos, registro, gestor de versiones
  interfaces/terminal/  interfaz de terminal
versions/0.1.0/manifest.json
```

## Riesgos técnicos

- **Un solo motor de base de datos.** La capa `storage/database.py` es la única que conoce
  `sqlite3`, pero la abstracción aún no está probada con otro motor.
- **Windows no verificado.** El desarrollo y las pruebas se hicieron en Linux. `launcher.ps1`
  no se ha ejecutado en Windows ni con PowerShell.
- **Sin aislamiento de procesos.** Ningún módulo se ejecuta todavía, así que no hay sandbox.
  Ver `docs/seguridad.md`.
- **Carga de versiones sin módulos.** Los manifiestos pueden declarar dependencias, pero
  mientras no exista el sistema de módulos, cualquier dependencia impide la carga.
