# CHANGELOG

## [Sin publicar]

- Fase 5: sistema de módulos declarativos (`modules/<id>/module.json`) con permisos de catálogo
  cerrado, descubrimiento tolerante a fallos, grafo de dependencias con detección de ciclos,
  habilitación y deshabilitación protegidas, estado persistente auditado y diagnóstico.
- Las versiones pueden requerir módulos habilitados. Antes, cualquier dependencia bloqueaba la
  carga sin posibilidad de resolverla.
- Terminal: opciones 10 a 13 para módulos.
- Migración 3: tabla `module_states`.
- 83 pruebas automatizadas.

## [0.1.0] - 2026-11-19

Reconstrucción del proyecto desde su commit inicial. El código anterior se eliminó y sigue
disponible en el historial de git (commit `3868286`).

- Fase 1: diagnóstico, arquitectura y documentación en `docs/`.
- Fase 2: núcleo con ciclo de vida validado, contenedor de servicios y bus de eventos.
- Fase 3 (parcial): configuración con esquema estricto, historial y copias restaurables solo
  con autorización; base SQLite con migraciones transaccionales; auditoría; copias verificadas
  por SHA-256.
- Fase 4 (parcial): manifiestos de versión, canal de distribución, carga manual, cambio,
  reversión e historial.
- Terminal interactiva.
- Punto de entrada `main.py` y lanzador `launcher.ps1` (este último sin probar en Windows).
- Pruebas automatizadas: 55, con ruff y mypy en modo estricto.
