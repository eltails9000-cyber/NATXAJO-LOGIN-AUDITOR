# Roadmap y estado de cada fase

Estado según lo verificado por pruebas automatizadas. Lo marcado como "pendiente" no existe en el
código, aunque aparezca en el documento maestro.

| Fase | Contenido | Estado |
|---|---|---|
| 1 | Inspección, diagnóstico, arquitectura y documentación | Hecha (`docs/diagnostico-inicial.md`, `docs/arquitectura.md`) |
| 2 | Núcleo, arranque, ciclo de vida, contenedor de servicios, bus de eventos | Hecha |
| 3 | Configuración, almacenamiento y migraciones | Parcial |
| 4 | Gestor de versiones y cargador manual | Parcial |
| 5 | Sistema de módulos y dependencias | Pendiente |
| 6 | Plugins, catálogo, firmas y compatibilidad | Pendiente |
| 7 | Seguridad, RBAC y sesiones | Pendiente |
| 8 | Motor de automatización | Pendiente |
| 9 | Motor de auditoría defensiva | Pendiente |
| 10 | Aplicación de escritorio | Pendiente |
| 11 | Diagnósticos, informes y analítica | Pendiente |
| 12 | Mantenimiento, actualizaciones y recuperación | Pendiente |
| 13 | Pruebas integrales, distribución | Pendiente |

## Lo implementado en las fases parciales

**Fase 3 (configuración y almacenamiento)**
- Hecho: configuración con esquema, validación, historial y restauración autorizada; base SQLite
  con migraciones transaccionales; auditoría; copias con SHA-256.
- Pendiente: perfiles predefinidos y personalizados, herencia y overrides, importación y
  exportación, comparación de configuraciones, copias incrementales, cifrado, control de acceso
  sobre la base de datos.

**Fase 4 (versiones)**
- Hecho: canales iniciales, manifiestos validados, registro desde `versions/`, validación de
  compatibilidad con el núcleo, carga manual, cambio, reversión e historial.
- Pendiente: ramas, etiquetas (tags), snapshots, canales personalizados, comparación detallada,
  clonación, exportación, archivado, editor avanzado y asistente de creación de versiones.
  También falta resolver dependencias reales, que llegará con la fase 5.

## Cómo añadir una fase

1. Escribir las pruebas primero, en `tests/`.
2. Implementar solo lo necesario para que pasen.
3. Actualizar esta tabla, `CHANGELOG.md` y la documentación afectada.
4. No marcar una fase como hecha si sus pruebas no pasan.
