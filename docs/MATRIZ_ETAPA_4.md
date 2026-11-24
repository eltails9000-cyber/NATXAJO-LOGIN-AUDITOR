# Matriz de la etapa 4: funcionalidad, archivos y pruebas

Rama `etapa-4-auditoria-informes-mantenimiento`, basada en `etapa-3-kernel-composicion`.

Estados:

- **Nuevo**: implementado en esta etapa y probado en Linux.
- **Existente**: ya estaba en etapas anteriores. Se verifica con las pruebas indicadas, sin cambios
  funcionales en esta etapa.
- **Parcial**: implementado con límites que se indican en la fila.
- **Pendiente**: no implementado. Se declara aquí y en `docs/IMPLEMENTATION_STATUS.md`.

Recuento de pruebas: 498 recogidas; 497 aprobadas, 0 fallidas y 1 omitida (análisis sintáctico del
lanzador, que requiere PowerShell). Las 173 pruebas nuevas de esta etapa están en los archivos
marcados con «nuevo».

## A. Motor de auditoría

| Requisito | Estado | Archivos | Pruebas |
|---|---|---|---|
| Motor central de análisis | Nuevo | `auditing/engine.py`, `auditing/service.py` | `test_auditoria_motor.py` (evaluación), `test_auditoria_servicio.py` |
| Registro de ejecuciones | Nuevo | `auditing/store.py`, `storage/migrations.py` (migración 10) | `test_auditoria_servicio.py`: round-trip, evaluación interrumpida, inmutabilidad |
| Reglas de auditoría configurables | Parcial: solo cinco reglas admiten sobrescritura, dentro de límites fijos | `auditing/catalog.py` | `test_auditoria_motor.py`: sobrescrituras, límites, cambio del texto esperado |
| Evaluación de políticas | Nuevo: perfiles `completo` (17 reglas) y `critico` (8 reglas) | `auditing/catalog.py`, `auditing/engine.py` | `test_auditoria_motor.py`: perfiles y nombres desconocidos |
| Detección de configuraciones inseguras | Nuevo, sin conexión: evalúa una configuración declarada, no un sistema en ejecución | `auditing/catalog.py`, `auditing/snapshot.py` | `test_auditoria_motor.py`: documento débil (17 fallos), documento correcto, `null` y secciones ausentes |
| Resultados estructurados | Nuevo | `auditing/results.py` | `test_auditoria_motor.py`: serialización en español |
| Historial de auditorías | Nuevo | `auditing/store.py`, `auditing/service.py` | `test_auditoria_servicio.py`: aislamiento del historial por empresa |
| Generación de informes | Nuevo | `reporting/` | `test_informes.py` |
| Validación de resultados | Nuevo | `auditing/results.py` (`validate_run`) | `test_auditoria_motor.py`: manipulaciones detectadas |
| Pruebas activas (TLS, HTTP, formularios) | Pendiente: requiere registro de alcance y autorización | — | — |

## B. Gestión de módulos

| Requisito | Estado | Archivos | Pruebas |
|---|---|---|---|
| Registro, descubrimiento, dependencias, compatibilidad, ciclo de vida, activación, estados persistentes, diagnóstico | Existente | `modules/` | `test_modules.py` (26), `test_dependencias.py` (5), `test_terminal_modules.py` (2) |
| Dependencias circulares | Existente | `modules/`, `kernel/` | `test_modules.py::test_dependency_cycle_is_reported`, `test_security_and_graph.py::test_dependency_cycle_is_detected` |
| Aislamiento de responsabilidades | Existente, verificado por reglas de capas | `docs/arquitectura.md` | `test_arquitectura.py` (16) |
| Ejecución de módulos | Pendiente | — | — |

## C. Gestión de plugins

| Requisito | Estado | Archivos | Pruebas |
|---|---|---|---|
| Catálogo local y repositorio | Existente | `plugins/` | `test_plugin_package.py` (34), `test_plugin_lifecycle.py` (15) |
| Manifiestos estrictamente validados | Existente | `plugins/` | `test_plugin_package.py::test_manifest_rejects_invalid_data`, `test_manifest_rejects_missing_fields` |
| Verificación de firmas e integridad | Existente | `core/ed25519.py`, `plugins/package.py` | `test_ed25519.py` (12), `test_plugin_package.py`: archivo alterado, añadido o eliminado, firma de otra clave, firma falsificada |
| Dependencias | Existente | `plugins/` | `test_plugin_lifecycle.py::test_enable_loads_dependencies_first_and_protects_them` |
| Instalación y desinstalación controladas | Existente | `plugins/` | `test_plugin_lifecycle.py` |
| Revisión de permisos antes de habilitar | Existente | `plugins/` | `test_plugin_lifecycle.py::test_third_party_plugin_needs_an_approved_review` |
| Registro de decisiones | Existente | `plugins/` | `test_plugin_package.py::test_review_log_keeps_history_and_latest_decision` |
| Actualización de plugins a una versión nueva del mismo editor | Nuevo: exige plugin deshabilitado, versión estrictamente mayor, mismo editor y copia verificada; conserva una versión anterior. Detalle en `docs/PLUGINS_CICLO.md` | `plugins/manager.py` (`update_package`), `storage/migrations.py` (migración 11) | `test_plugins_ciclo.py`: actualización, retirada de la copia anterior, editor distinto, versión repetida, paquete alterado, editor revocado |
| Rollback de plugins | Nuevo: intercambia la versión activa con la anterior; exige plugin deshabilitado y copia verificada | `plugins/manager.py` (`rollback`) | `test_plugins_ciclo.py`: intercambio ida y vuelta, copia alterada o ausente, sin versión anterior, deshabilitado. `test_versioning.py` sigue probando solo el núcleo |
| Cuarentena | Nuevo: por versión, bloquea la habilitación, deshabilita los dependientes habilitados y se libera con confirmación y reautenticación | `plugins/manager.py` (`quarantine`, `release_quarantine`) | `test_plugins_ciclo.py`: bloqueo, cascada, liberación, reversión que no evade la cuarentena; `test_migracion_11.py` |
| Ejecución de plugins | Pendiente: sin modelo de aislamiento ni autorización. Ningún código de plugin se ejecuta | — | — |

## D. Seguridad y autenticación

| Requisito | Estado | Archivos | Pruebas |
|---|---|---|---|
| Políticas de contraseñas | Existente | `security/passwords.py` | `test_security.py` |
| Sesiones y expiración | Existente, probado | `security/sessions.py` | `test_security.py::test_idle_session_expires`, `test_activity_renews_the_idle_timeout`, `test_absolute_timeout_expires_even_an_active_session`, `test_expired_session_returns_to_the_login_prompt`; `test_auditoria_servicio.py::test_an_invalid_session_is_rejected_before_anything_happens` |
| Bloqueo temporal ante intentos fallidos | Existente | `security/` | `test_security.py::test_failed_logins_lock_the_account_until_the_lockout_expires`, `test_locked_account_answers_exactly_like_an_unknown_user`; `test_auditoria_postimplementacion.py` (concurrencia) |
| Control de acceso por roles y permisos | Existente | `core/permissions.py`, `security/` | `test_security.py::test_separation_of_duties_blocks_operator_and_auditor_together`; `test_auditoria_servicio.py` (operador y auditor) |
| Protección contra escalamiento | Existente, ampliado: el guardián aplica ámbito de empresa y confirmación | `security/guard.py` | `test_companies.py`, `test_editores_confianza.py`, `test_auditoria_servicio.py` |
| Auditoría de operaciones sensibles | Existente, ampliado a evaluaciones, informes y limpieza | `security/guard.py`, `storage/audit.py` | `test_auditoria_servicio.py`, `test_informes.py`, `test_mantenimiento.py` |
| Sin fuerza bruta ni recolección de credenciales | Diseño: no existe código con esa función | — | — |

## E. Informes

| Requisito | Estado | Archivos | Pruebas |
|---|---|---|---|
| Informes JSON, CSV, HTML y TXT | Nuevo | `reporting/formats.py` | `test_informes.py`: contenido de cada formato |
| Historial consultable | Nuevo | `reporting/service.py` | `test_informes.py`: historial y aislamiento por empresa |
| Identificadores únicos, fechas y versiones | Nuevo | `reporting/formats.py`, `reporting/service.py` | `test_informes.py`: `test_json_is_valid_and_carries_the_methodology_and_the_evaluation` |
| Registro de errores | Nuevo: `report.failed` con motivo recortado | `reporting/service.py` | `test_informes.py::test_a_failed_export_leaves_no_file_and_no_row_and_is_recorded` |
| Exportación segura | Nuevo: escritura atómica, empresa validada, neutralización CSV, escape HTML, verificación de huellas | `reporting/service.py`, `reporting/formats.py` | `test_informes.py`: fórmulas CSV, HTML escapado, `test_verification_detects_altered_missing_and_orphan_files` |

## F. Interfaz de terminal

| Requisito | Estado | Archivos | Pruebas |
|---|---|---|---|
| Mejora de la terminal existente | Nuevo: opciones 20 a 28 | `interfaces/terminal/app.py`, `console.py`, `operaciones.py` | `test_terminal_etapa4.py` (10) |
| Estado y cambios de plugins desde la terminal | Nuevo: opciones 29 a 33 (estado, cuarentena, liberación, actualización y reversión) | `interfaces/terminal/operaciones_plugins.py`, `app.py` | `test_terminal_plugins.py` (8) |
| Menús y comandos organizados | Nuevo: acciones por áreas en `operaciones.py`; tipos compartidos en `console.py` | `interfaces/terminal/` | `test_terminal.py` (9), `test_terminal_modules.py` (2) |
| Mensajes de error claros | Nuevo para las opciones nuevas | `interfaces/terminal/operaciones.py` | `test_terminal_etapa4.py`: sobrescritura no válida, reautenticación requerida |
| Estado del núcleo, cuentas, empresas, permisos | Existente | `interfaces/terminal/app.py` | `test_companies.py` (16), `test_security.py` |
| Gestión de módulos y plugins desde la terminal | Parcial: módulos y, desde esta etapa, estado, cuarentena, actualización y reversión de plugins. Instalación y habilitación de plugins desde la terminal: pendiente | `interfaces/terminal/app.py` | `test_terminal_modules.py`, `test_terminal_plugins.py` |
| Preparación para una interfaz de escritorio | Nuevo, sin simular que existe: los servicios devuelven datos planos sin tipos de subsistema | `interfaces/` | `test_arquitectura.py` |
| Interfaz de escritorio | Pendiente (fase 10) | — | — |

## G. Mantenimiento

| Requisito | Estado | Archivos | Pruebas |
|---|---|---|---|
| Diagnóstico general | Nuevo: ocho comprobaciones | `maintenance/diagnostics.py`, `maintenance/service.py` | `test_mantenimiento.py` (13) |
| Verificación de integridad | Existente y ampliado al diagnóstico | `storage/database.py`, `storage/backups.py` | `test_storage.py` (12) |
| Copias de seguridad | Existente | `storage/backups.py` | `test_storage.py` |
| Restauración con autorización | Parcial: existe en la API con autorización explícita y hash verificado; la terminal no la expone | `storage/backups.py`, `configuration/manager.py` | `test_storage.py::test_restore_requires_authorization`, `test_restore_refuses_altered_backup`; `test_configuration.py::test_backup_restore_requires_authorization` |
| Limpieza segura de temporales | Nuevo: solo `*.tmp` regulares en carpetas gestionadas, sin enlaces, con confirmación y reautenticación | `maintenance/cleanup.py` | `test_mantenimiento.py` (incluye enlaces y archivos fuera de carpetas gestionadas) |
| Comprobación de migraciones | Nuevo: pendientes en el diagnóstico y guardia de SQLite en la reversión | `storage/migrations.py`, `maintenance/diagnostics.py` | `test_migraciones_etapa4.py` (10), `test_migrations_stage2.py` (8) |
| Recuperación ante errores | Nuevo: transacciones atómicas, limpieza de temporales, reporte de fallos | varios | ver `docs/MANTENIMIENTO.md`, sección «Recuperación ante errores» |

## Transversal: pruebas obligatorias

| Prueba exigida | Dónde está |
|---|---|
| Migraciones desde una base nueva | `test_migraciones_etapa4.py::test_a_fresh_database_gets_every_evaluation_table_and_trigger`; `test_storage.py::test_migrations_apply_once` |
| Migraciones desde una instalación anterior | `test_migraciones_etapa4.py::test_upgrade_from_v9_keeps_every_row_and_adds_the_evaluation_tables` (datos de la versión 9); `test_migrations_stage2.py` (datos de la versión 5) |
| Recuperación ante interrupciones | `test_migraciones_etapa4.py::test_recovery_after_an_interruption_applies_the_real_migration`; `test_auditoria_servicio.py::test_an_interrupted_evaluation_leaves_no_rows_behind`; `test_informes.py::test_a_failed_export_leaves_no_file_and_no_row_and_is_recorded` |
| Permisos y aislamiento entre empresas | `test_auditoria_servicio.py` (empresas, operador, auditor); `test_informes.py`; `test_terminal_etapa4.py::test_a_company_administrator_sees_and_runs_only_its_own_company`; `test_mantenimiento.py::test_company_administrators_cannot_diagnose_or_clean` |
| Sesiones y expiración | `test_security.py` (inactividad, absoluta, reautenticación, sesión caducada) |
| Plugins inválidos y firmas incorrectas | `test_plugin_package.py`, `test_ed25519.py` |
| Dependencias circulares | `test_modules.py`, `test_security_and_graph.py`, `test_arquitectura.py` |
| Rollback | `test_versioning.py` (núcleo), `test_migrations_stage2.py` y `test_migraciones_etapa4.py` (migraciones), `test_plugins_ciclo.py` (versiones de plugins) |
| Exportación de informes | `test_informes.py` |
| Rutas con espacios y caracteres especiales | `test_auditoria_motor.py::test_documents_in_folders_with_spaces_and_special_characters_are_read`; `test_auditoria_servicio.py` (carpeta y raíz del proyecto con espacios); `test_informes.py` (raíz con Unicode); `test_terminal_etapa4.py` (ruta entre comillas); `test_lanzador.py` (rutas literales) |
| Las pruebas no modifican datos reales | `test_aislamiento_pruebas.py`; todas las pruebas usan `tmp_path` |
| No se filtran secretos en logs ni informes | Parcial: `test_auditoria_motor.py::test_rejection_messages_never_repeat_the_received_secret` cubre los mensajes de rechazo. No hay una prueba que busque secretos en el contenido de los informes; el contenido solo incluye campos del esquema |

## Lanzador de Windows

| Requisito | Estado | Archivos | Pruebas |
|---|---|---|---|
| Python 3.11 o posterior, alias de la Microsoft Store ignorados, instalaciones reales, errores claros, códigos de salida, argumentos, rutas con espacios, política de ejecución sin cambios | Nuevo en el texto del script. Windows y PowerShell no están disponibles en este entorno: el lanzador no se ha ejecutado | `launcher.ps1` | `test_lanzador.py` (10; 1 omitida si no hay PowerShell) |
