# Mantenimiento

Estado: diagnóstico y limpieza implementados y probados en Linux (etapa 4). Windows no verificado.

El mantenimiento es de **plataforma**: solo las cuentas de la empresa `plataforma` lo usan. El
diagnóstico no repara nada; indica qué revisar. La única acción que borra archivos es la limpieza de
temporales, y exige confirmación y reautenticación recientes.

## Diagnóstico

`diagnose(token)` ejecuta ocho comprobaciones de solo lectura. Cada una devuelve un estado y un detalle
en español.

| Comprobación | Qué mira | `ok` | `aviso` | `error` |
|---|---|---|---|---|
| `python` | Versión del intérprete | 3.11 o posterior | — | anterior a 3.11 |
| `sqlite` | Versión de SQLite | 3.35.0 o posterior | anterior a 3.35.0 (revertir las migraciones 6 y 8 la necesita) | — |
| `base_de_datos` | `PRAGMA integrity_check` | `ok` | — | cualquier otro resultado |
| `migraciones` | Versiones pendientes | todas aplicadas | hay pendientes | — |
| `eventos` | Eventos fallidos y pendientes de entrega | sin fallidos | hay eventos fallidos | — |
| `copias` | Integridad de las copias (`BackupManager.integrity`) | sanas | — | hay problemas |
| `temporales` | Archivos `*.tmp` en las carpetas gestionadas | ninguno | hay alguno | — |
| `escritura` | Que las carpetas gestionadas se puedan escribir | escribibles | — | alguna no se puede escribir |

El estado general es el peor de los ocho: `error` si alguno falla, `aviso` si alguno avisa y `ok` en
otro caso.

Las carpetas gestionadas son `config/`, `storage/` y `reports/`, con sus subcarpetas directas.

## Limpieza de temporales

Un temporal es un archivo regular cuyo nombre termina en `.tmp` dentro de una carpeta gestionada. Los
escritores atómicos del proyecto crean un `.tmp` junto al destino y lo sustituyen al terminar; si el
proceso se interrumpe, el `.tmp` queda. La limpieza solo borra esos archivos.

Reglas:

- Nunca borra bases de datos, copias, informes, configuración ni ningún archivo sin el sufijo.
- Nunca sigue enlaces simbólicos, ni los considera temporales.
- Nunca toca archivos fuera de las carpetas gestionadas.
- Solo mira las subcarpetas directas: `reports/<empresa>/` sí, `reports/<empresa>/<otra>/` no.
- La antigüedad se mide con la fecha de modificación y debe estar entre 1 y 8760 horas. El valor por
  defecto es 24.

Dos operaciones:

1. `plan_cleanup(token, antigüedad)`: lista los temporales que se borrarían. No borra nada. Permiso
   de diagnóstico.
2. `apply_cleanup(token, antigüedad, confirmada)`: vuelve a calcular el plan en el momento de aplicar,
   borra solo los archivos que siguen cumpliendo las reglas y registra el evento
   `maintenance.cleanup_applied` con los archivos eliminados. Es una operación **crítica**: sin
   confirmación explícita o sin reautenticación reciente, no hace nada.

Devuelve `planeados` y `eliminados`. Si entre el plan y la aplicación un archivo cambia o desaparece,
no se borra y no cuenta como eliminado.

## Permisos

| Operación | Permiso | Ámbito |
|---|---|---|
| Diagnóstico y plan de limpieza | `mantenimiento:nucleo:diagnostico:leer` | solo plataforma |
| Aplicar la limpieza | `mantenimiento:nucleo:limpieza:ejecutar` | solo plataforma, crítica |

Una cuenta de empresa, aunque tenga rol de administrador, recibe «acceso denegado» en todas estas
operaciones. La prueba `test_company_administrators_cannot_diagnose_or_clean` lo cubre.

## Terminal

- Opción 26: diagnóstico general, con el estado de cada comprobación y su detalle.
- Opción 27: limpieza en dos pasos. Primero se muestra el plan con su antigüedad; después se pide la
  confirmación. Si no hay temporales, termina sin preguntar. Si la sesión no está reautenticada, la
  limpieza se rechaza y los archivos se conservan.

## Recuperación ante errores

Lo que el sistema hace cuando algo se interrumpe, y dónde está probado:

| Situación | Comportamiento | Prueba |
|---|---|---|
| Migración que falla a mitad | La transacción se revierte. La base queda en la versión anterior y se puede volver a migrar | `test_an_interrupted_evaluation_migration_leaves_the_v9_schema_intact`, `test_recovery_after_an_interruption_applies_the_real_migration` |
| Evaluación que falla al guardarse | No queda ninguna fila de la evaluación ni de sus hallazgos | `test_an_interrupted_evaluation_leaves_no_rows_behind` |
| Exportación que falla al registrarse | Se borra el archivo, no queda fila y se registra `report.failed` | `test_a_failed_export_leaves_no_file_and_no_row_and_is_recorded` |
| Temporal dejado por un corte | `temporales` lo reporta como `aviso`; la limpieza lo borra tras confirmación | `test_a_leftover_temporary_file_is_reported_as_a_warning` |
| Reversión de migraciones con SQLite antiguo | Se comprueba la versión antes de cambiar nada | `test_the_rollback_checks_the_sqlite_version_before_changing_anything` |

No existe una herramienta general de reparación automática. Una base dañada se diagnostica con la
opción 26. La restauración desde una copia de la base de datos no está expuesta: `kernel.backups`
tiene `restore`, pero sin guardián ni llamadores, y restaurar sobre la base viva sobrescribiría datos.

## Restauración de copias

`storage.backups` puede restaurar una copia, pero solo si su hash coincide con el registrado al
crearla y con autorización explícita. **La terminal no expone esa operación todavía.** Queda pendiente
junto con su confirmación y su reautenticación (`docs/IMPLEMENTATION_STATUS.md`).

## Pendiente

- Restauración de copias desde la terminal, con confirmación y reautenticación.
- Reparación automática de incidencias. El diagnóstico solo informa.
- Comprobación de migraciones desde una instalación anterior real (la cobertura usa una base
  construida con las migraciones 1 a 9, no una copia de una instalación en producción).
