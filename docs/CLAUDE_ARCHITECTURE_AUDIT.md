# Auditoría de arquitectura: NATXAJO-LOGIN-AUDITOR

Etapa 1 de la especificación corporativa. Fecha: 2026-11-20. Commit auditado: `16cbcf9`
(Fase 7 parcial). Esta auditoría no modifica código funcional; las correcciones van en etapas
posteriores, según el orden de la sección 13.

## 1. Alcance y método

- **Inventario.** 55 módulos Python en `src/` (4 453 líneas), 13 archivos de prueba (2 426 líneas),
  4 documentos en `docs/`, y `README.md`, `CHANGELOG.md`, `LICENSE`, `pyproject.toml`, `main.py` y
  `launcher.ps1`. No hay archivos vacíos en el repositorio.
- **Lectura.** Kernel, contexto, base de datos, migraciones, autorización, sesiones, cuentas,
  guardián, terminal, gestores de módulos, plugins y versiones, y configuración.
- **Búsqueda sistemática.** Llamadas a cada servicio, escrituras sin transacción, funciones
  duplicadas, marcadores de trabajo pendiente, suscriptores del bus de eventos, y dependencias
  entre paquetes.
- **Comprobaciones dinámicas.** Un script contra el núcleo real para el comportamiento del bloqueo
  de cuentas, y una medición del coste de PBKDF2.
- **Estado de las herramientas.** `pytest`: 213 casos pasan. `ruff check` y `ruff format --check`:
  limpios. `mypy --strict` sobre 55 archivos: sin errores.

## 2. Estado actual

| Componente | Estado | Observación |
|---|---|---|
| Núcleo y ciclo de vida | Probado | Arranque fallido deja el núcleo en `FAILED` y cierra los servicios. |
| Base de datos y migraciones 1 a 5 | Probado | Migraciones transaccionales. Una base con migraciones desconocidas se rechaza. |
| Configuración | Probado, desconectado | No está en la terminal. Varias claves no las usa nada. |
| Versiones | Probado | Carga, cambio y reversión con auditoría en la misma transacción. |
| Módulos | Probado | Los permisos se validan pero no se aplican: no hay ejecución. |
| Plugins | Probado | Firma, integridad, editores y ciclo de vida. No se ejecutan. Sin opciones de terminal. |
| Seguridad (fase 7) | Probado | Autorización aplicada solo desde la terminal (ver P-01). |
| Copias de seguridad | Parcial | Solo la configuración crea copias. La base de datos no se copia nunca (ver P-06). |
| Auditoría | Parcial | Registra eventos, sin encadenado ni firma (ver R-03). |
| Terminal | Probado | 463 líneas. Mezcla presentación con orquestación (ver P-15). |
| Multiempresa, aplicaciones, entornos | No existe | Requisito principal de la especificación. |
| Automatización, escritorio, informes, diagnósticos avanzados | No existe | Etapas 11 a 14. |

## 3. Puntos de entrada

- `main.py` (raíz): añade `src/` al `sys.path` y llama a `natxajo_auditor.main.main`. Permite
  `python main.py` sin instalar el paquete.
- `src/natxajo_auditor/main.py`: analiza `--version`, crea `Kernel(RuntimeContext(cwd))`, arranca,
  ejecuta la terminal y detiene el núcleo al salir.
- `natxajo-auditor`: comando de consola declarado en `pyproject.toml`, que apunta al mismo `main`.
- `launcher.ps1`: busca Python 3.11 o posterior (`py -3.11`, `py -3`, `python`) y ejecuta `main.py`.
  No se ha probado en Windows.
- Terminal (`interfaces/terminal/app.py`): única interfaz de usuario. No hay API de red, ni CLI de
  subcomandos, ni aplicación de escritorio.

## 4. Kernel

- **Composición en el núcleo.** `Kernel.start` (`kernel/kernel.py`, líneas 62 a 118) crea
  directamente `ConfigurationManager`, `BackupManager`, `ModuleManager`, `VersionManager`,
  `PluginManager` y `SecurityService`. El núcleo conoce todos los subsistemas y debería solo
  componerlos. Ver P-12.
- **Accesores sin tipos verificados.** `ServiceContainer` guarda objetos por cadena y las propiedades
  del kernel usan `cast`. `ServiceContainer` no valida el tipo al registrar: un servicio de tipo incorrecto solo falla al usarse.
- **Ciclo de vida.** Transiciones validadas, parada idempotente y arranque con limpieza. Verificado
  en `tests/test_kernel.py`.
- **Bus de eventos sin consumidores.** `EventBus.publish` solo se llama con `kernel.started` y
  `kernel.stopped`. `subscribe` no tiene ningún uso en `src/`. Es funcionalidad desconectada (ver P-08).
- **Inyección para pruebas.** `password_iterations` (mínimo 1 000) y `clock` se inyectan. Es una
  buena práctica y permite pruebas deterministas.

## 5. Subsistemas

| Subsistema | Archivos | Estado | Observaciones |
|---|---|---|---|
| `core` | `validation`, `graph`, `ed25519`, `utilities`, `exceptions` | Probado | No depende de nada del proyecto. `ed25519` no es de tiempo constante; está documentado. |
| `storage` | `database`, `migrations`, `audit`, `backups` | Probado | Una sola conexión SQLite en autocommit, con `transaction()` para escrituras atómicas. |
| `configuration` | `manager`, `schema` | Probado, desconectado | Escritura atómica y historial. `restore` usa un booleano `authorized`, no permisos. |
| `versioning` | `manifest`, `registry`, `manager`, `channels` | Probado | `versions/0.1.0/` contiene solo `manifest.json`: la versión es declarativa. |
| `modules` | `manifest`, `discovery`, `dependency_graph`, `manager` | Probado | `enable` y `disable` en transacción con auditoría. |
| `plugins` | `manifest`, `package`, `verifier`, `trust`, `review`, `repository`, `store`, `manager`, `api` | Probado | `manager.py` tiene 357 líneas y concentra demasiadas responsabilidades (P-18). |
| `security` | `passwords`, `roles`, `accounts`, `grants`, `sessions`, `authorization`, `guard`, `service`, `permissions` | Probado | Es el subsistema con más huecos de atomicidad y de aplicación (P-01, P-02, P-03). |
| `interfaces/terminal` | `app.py` | Probado | Presentación, flujo de inicio de sesión y despacho de opciones en un solo archivo. |

Dependencias observadas entre paquetes (importaciones reales):

- `kernel` → `configuration`, `storage`, `versioning`, `modules`, `plugins`, `security`.
- `configuration` → `storage.backups`.
- `versioning` → `storage`, `core`. Recibe `modules.is_enabled` como función inyectada, no como import.
- `modules` y `plugins` → `core` y `security.permissions` (solo para validar el formato de permisos).
- `security` → `storage`, `core`.
- `interfaces.terminal` → `kernel`, `security.sessions` (`SessionError`), `core.exceptions`.
- Ningún paquete distinto de `kernel` importa `interfaces`. Ningún paquete distinto de `interfaces`
  y `kernel` importa `kernel`. Estas dos reglas se cumplen.

## 6. Problemas detectados

Cada problema tiene evidencia en el código. Los marcados como **P0** se tratan antes de añadir
funcionalidad nueva.

### P-01 (P0) La autorización solo existe en la terminal

`OperationGuard.run` se llama en un único lugar: `interfaces/terminal/app.py:145`. Los métodos que
cambian estado no comprueban permisos por sí mismos:

- `modules/manager.py`: `enable` (60), `disable` (85).
- `plugins/manager.py`: `install_package` (76), `install_from_repository` (87), `enable` (146),
  `disable` (179), `uninstall` (203), `record_review` (223), `revoke_publisher` (236).
- `versioning/manager.py`: `load` (66).
- `storage/backups.py`: `restore` (66).
- `configuration/manager.py`: `restore` (48), que usa un booleano `authorized`.
- `security/service.py`: `create_account` (48), `disable_account` (61).
- `security/accounts.py`: `create` (81), `set_status` (151), `set_roles` (173).
- `security/grants.py`: `approve` (76), `reject` (101), `revoke` (110).

Cualquier código que use `kernel.plugins`, `kernel.security` o `kernel.modules` salta el control de
acceso. Una interfaz nueva (escritorio, automatización) heredaría ese fallo si no añade su propio
guardián. Es el riesgo más importante para la dirección multiempresa.

### P-02 (P0) Oráculo de enumeración de cuentas durante el bloqueo. Confirmado

`security/accounts.py`, `check_password`: el bloqueo se comprueba antes de verificar la contraseña
(líneas 128 a 130). Resultado de la comprobación dinámica con un núcleo real, después de cinco
fallos:

| Caso | Mensaje |
|---|---|
| Usuario inexistente, contraseña mala | `credenciales no válidas` |
| Usuario real sin bloqueo, contraseña mala | `credenciales no válidas` |
| Usuario real bloqueado, contraseña mala | `cuenta bloqueada temporalmente; inténtelo más tarde` |
| Usuario real bloqueado, contraseña buena | `cuenta bloqueada temporalmente; inténtelo más tarde` |

Quien prueba nombres de usuario puede saber cuáles existen en cuanto provoca un bloqueo. El docstring
del módulo promete lo contrario ("Un error de inicio de sesión no revela si el usuario existe"), y
`docs/seguridad.md` lo repetía sin matices. El test
`test_unknown_user_gets_the_same_message_as_a_wrong_password` pasa porque no prueba el estado
bloqueado. Se corrige en esta etapa (sección 12).

### P-03 (P1) Cambios de estado sin transacción junto a su auditoría

Estas escrituras usan `execute` fuera de `transaction()`, y su evento de auditoría va después en
otra escritura separada. Si el proceso se interrumpe entre ambas, queda el cambio sin registro:

- `security/accounts.py`: contador de fallos y `account.login_failed` (134 a 139); reinicio del
  contador y `account.authenticated` (141 a 148); `set_status` (157 a 161); `change_password`
  (166 a 171).
- `security/sessions.py`: expiración de sesión y `session.expired` (81 a 84); `reauthenticate`
  (127 a 130).

Las escrituras de cuentas nuevas, roles, sesiones abiertas o cerradas, permisos temporales,
versiones, módulos y plugins sí van en `transaction()` con el auditor dentro (verificado con
`grep`).

### P-04 (P1) El primer administrador lo crea quien llegue primero

`interfaces/terminal/app.py`, `_bootstrap` (línea 77): cuando no hay cuentas, cualquiera que use la
terminal crea el administrador. No hay código de instalación, ni token, ni restricción a ejecución
local. Es un diseño aceptable para un equipo de uso personal, pero no para una plataforma
corporativa.

### P-05 (P0) El registro de editores de confianza no se audita ni se protege

`plugins/trust.py`, `add_publisher` (42): inserta en `plugin_publishers` con `execute` y no registra
evento de auditoría. Lo llama solo `tests/conftest.py:124`. Un editor registrado es una raíz de
confianza: sus plugins quedan admisibles. Su alta debe exigir permiso, quedar auditada y tener una
acción de la terminal o de la API protegida.

### P-06 (P1) La base de datos no tiene copia de seguridad

`kernel/kernel.py:69` abre `storage/natxajo.db`. Ninguna ruta de ejecución copia ese archivo.
`storage/backups.py` (`BackupManager.create`) solo lo llama `configuration/manager.py:46` para la
configuración. El `BackupManager` del núcleo solo se usa para `integrity()` (terminal, opción 8).
No hay recuperación posible de la base de datos desde la aplicación.

### P-07 (P2) Una sola conexión SQLite, sin preparación para hilos

`storage/database.py:28` abre `sqlite3.connect(..., isolation_level=None)` sin `check_same_thread`
y sin modo WAL explícito. El tiempo de espera es el de `sqlite3` por defecto (5 segundos). Hoy todo
funciona en un solo hilo. La aplicación de escritorio (etapa 12) y la automatización (etapa 11)
necesitarán una estrategia explícita: conexión por hilo o cola de escritura.

### P-08 (P2) Bus de eventos sin consumidores

Ver sección 4. Decisión pendiente: conectarlo a la auditoría y a la futura interfaz de escritorio,
o retirarlo. No se retira sin justificación, según la regla de protección del repositorio.

### P-09 (P2) Documentación de arquitectura desactualizada

`docs/arquitectura.md`:

- El diagrama de capas (líneas 5 a 7) solo muestra `kernel`, `configuration`, `storage`,
  `versioning` y `core`. Faltan `modules`, `plugins` y `security`.
- La tabla "Dónde vive cada cosa" no incluye plugins ni las tablas de seguridad.
- La decisión D9 aparece antes de D8.

`docs/diagnostico-inicial.md` describe la Fase 1 y debe marcarse como histórico.

### P-10 (P2) Duplicación de lógica entre módulos y plugins

`modules/manager.py` y `plugins/manager.py` implementan por separado la habilitación, la
deshabilitación, la lista de habilitados y el cierre de dependencias (`enable`, `disable`,
`enabled_ids`, `dependents_of`). Las reglas ya están en `core/graph.py`, pero el flujo de estado no
está compartido.

### P-11 (P2) Duplicación de historial y copia en configuración

La configuración tiene su propio historial (`config/history/`) y, además, copias con
`BackupManager` (`config/backups/`). Son dos mecanismos para casi la misma necesidad.

### P-12 (P2) El kernel conoce todos los subsistemas

Ver sección 4. Una composición en un módulo aparte (`bootstrap`) con factorías registradas
permitiría añadir subsistemas sin tocar el kernel.

### P-13 (P3) Helper de pruebas duplicado

`_scripted` aparece en `tests/test_security.py`, `tests/test_terminal.py` y
`tests/test_terminal_modules.py`.

### P-14 (P2) Configuración desconectada y claves sin uso

Sin conexión a la terminal. Sin uso en código: `general.theme`, `general.locale`, `general.level`,
`logging.level`, `logging.structured`, `auditing.enabled`, `auditing.max_requests`. Documentado
en `docs/IMPLEMENTATION_STATUS.md`. Un esquema que acepta claves sin efecto da una falsa sensación de
control.

### P-15 (P2) La terminal concentra presentación y orquestación

`interfaces/terminal/app.py` tiene 463 líneas: menú, despacho, confirmaciones, reautenticación y
los flujos de cada opción. Las reglas de negocio no están ahí, pero el flujo de cada operación sí.
Una segunda interfaz tendría que duplicarlo.

### P-16 (P2) Sin medición de cobertura ni pruebas de arquitectura

- No hay `pytest-cov` ni umbral de cobertura.
- Ninguna prueba comprueba las reglas de dependencia entre capas. Hoy se cumplen, pero nada lo
  asegura.

### P-17 (P3) Dependencias de desarrollo sin fijar

`pyproject.toml` declara `pytest>=8.0`, `ruff>=0.6` y `mypy>=1.11`, sin archivo de bloqueo. Dos
instalaciones pueden dar resultados distintos de ruff o mypy.

### P-18 (P2) `plugins/manager.py` es demasiado grande

357 líneas: instalación, habilitación, deshabilitación, desinstalación, revisión y revocación en una
sola clase. Candidato a dividir por responsabilidad, con el mismo contrato público.

### P-19 (P3) Lanzador de Windows sin probar

`launcher.ps1` no se ha ejecutado en Windows. No hay PowerShell en el entorno de desarrollo.

### Lo que está bien

Estas partes se comprobaron y no requieren cambios de fondo:

- Escritura atómica de configuración (temporal y sustitución) con historial.
- Migraciones transaccionales, con rechazo de esquemas desconocidos.
- Fichas de sesión guardadas solo como hash SHA-256; comparación de hashes con
  `hmac.compare_digest`.
- PBKDF2 con sal aleatoria, mínimo de iteraciones y formato validado; un registro malformado no
  verifica.
- Verificación de plugins en orden fijo (firma, editor, integridad, manifiesto, compatibilidad); la
  copia almacenada se vuelve a verificar antes de habilitarla; limpieza de la copia si falla la
  instalación.
- Los mensajes de auditoría contienen nombres de usuario, roles e identificadores de plugin, no
  contraseñas ni fichas (revisado en las llamadas a `record(` de `src/`).

## 7. Riesgos técnicos

| Id | Riesgo | Probabilidad | Impacto | Mitigación |
|---|---|---|---|---|
| R-01 | Operación privilegiada ejecutada sin permiso desde una interfaz nueva | Alta si se añaden interfaces | Alto | Autorización obligatoria en los casos de uso (P-01). |
| R-02 | Enumeración de cuentas durante el bloqueo | Confirmada | Medio | Corregida en la etapa 1 (P-02). |
| R-03 | Alteración de la auditoría sin detección | Media | Alto | Encadenado con hash previo y verificación (etapa 10). |
| R-04 | Pérdida de datos sin copia de la base | Media | Alto | Copia y restauración de `natxajo.db` (etapa 9). |
| R-05 | Fuga de datos entre empresas al añadir multiempresa | Alta si se añade sin modelo previo | Muy alto | Columna de empresa obligatoria y pruebas de aislamiento cruzado (etapa 4). |
| R-06 | Cambio sin registro tras una interrupción | Baja | Medio | Transacción única por cambio y auditoría (P-03). |
| R-07 | Editor de confianza añadido sin rastro ni permiso | Media | Alto | Permiso y auditoría en el alta (P-05). |
| R-08 | Denegación de servicio sobre cuentas conocidas por bloqueo | Media | Medio | Bloqueo por cuenta con desbloqueo administrado, o límites por origen cuando exista red. |
| R-09 | Datos en texto plano en disco | Media | Alto en entorno corporativo | Cifrado en reposo y decisión sobre gestión de claves (etapa 9). |
| R-10 | Escrituras desde hilos distintos con SQLite | Media al añadir escritorio | Medio | Estrategia de conexión por hilo o cola de escritura (P-07). |
| R-11 | Documentación que contradice el código | Media | Medio | Revisión de documentación en cada etapa (P-09, P-02). |
| R-12 | Lanzador de Windows roto | Media | Medio | Prueba manual en Windows antes de publicar (etapa 15). |
| R-13 | Interpretación de pruebas verdes como seguridad | Media | Alto | Pruebas de cada defensa, incluido el caso negativo (P-02 mostró el hueco). |

## 8. Dependencias

- **Ejecución:** ninguna dependencia externa. Solo biblioteca estándar de Python 3.11 o posterior.
  Ed25519 y PBKDF2 se implementan o usan desde `hashlib`.
- **Desarrollo:** `pytest>=8.0`, `ruff>=0.6`, `mypy>=1.11`.
- **Construcción:** `setuptools>=68`.
- **Pendiente:** la generación de informes PDF necesita una dependencia no disponible hoy. La
  instalación de paquetes está bloqueada en este entorno, así que no se ha añadido.
- **Sin archivo de bloqueo** (P-17).
- **Sistema:** Windows 10 u 11 para el lanzador; PowerShell no probado.

## 9. Componentes incompletos o desconectados

- Configuración: sin conexión a la terminal; claves sin efecto (P-14).
- Bus de eventos: sin consumidores (P-08).
- Permisos de módulos: validados, no aplicados. No hay ejecución de código de módulos.
- Plugins: no se ejecutan; sin opciones de terminal; sin actualización de versión; sin repositorio
  remoto.
- Copias de almacenamiento: solo verificación de integridad. No se crean ni se restauran desde la
  aplicación (P-06).
- Versiones: `versions/0.1.0/` contiene solo `manifest.json`. No hay ramas, etiquetas ni snapshots.
- Auditoría: consulta y listado. No hay motor de auditoría de autenticación.
- Diagnósticos: estado de servicios, diagnóstico de módulos e integridad de copias. No hay informes.
- Automatización, aplicación de escritorio, informes y multiempresa: no existen.
- Lanzador de Windows: no probado. Carpetas `powershell/` y `scripts/`: no creadas.

## 10. Persistencia y seguridad de datos

- **Persistencia:** un archivo SQLite (`storage/natxajo.db`), migraciones 1 a 5 (`platform_metadata`,
  `audit_events`, `module_states`, `plugins` y tablas de plugins, `seguridad`). La configuración es
  JSON en `config/`, con historial. Los plugins se copian en `storage/plugins/`.
- **Texto plano:** base de datos, configuración, historial y copias. Solo las contraseñas van como
  hash PBKDF2; las fichas de sesión como SHA-256.
- **Auditoría:** sin encadenado ni firma. Quien escriba en la base puede alterarla sin detección.
- **Permisos de archivos:** los del sistema operativo por defecto. No se restringen las carpetas de
  datos.
- **Restauración:** la configuración exige `authorized=True` (booleano). Las copias de almacenamiento
  verifican SHA-256 antes de restaurar. Ninguna de las dos usa el modelo de permisos.

## 11. Pruebas

- **Estado:** 213 casos. 174 funciones de prueba, 9 apariciones de `parametrize`. 13 archivos. Todos pasan.
- **Lo que cubren bien:** atomicidad de versiones y módulos, persistencia tras reinicio, flujo de
  plugins, lógica de sesiones y reglas de roles.
- **Huecos:**
  - Ninguna prueba del estado bloqueado frente a usuario inexistente (P-02).
  - Autorización probada solo desde la terminal, no en los servicios (P-01).
  - Ningún fallo a mitad de transacción en seguridad (P-03).
  - Ninguna prueba de aislamiento entre empresas (no existen).
  - Ninguna prueba de concurrencia ni de hilos (P-07).
  - Ninguna prueba de restauración de la base de datos (no existe la función, P-06).
  - Lanzador de Windows sin prueba.
  - Sin medición de cobertura (P-16).

## 12. Correcciones aplicadas en esta etapa

Se aplica solo lo que corrige un defecto confirmado y que contradice la documentación:

- **P-02:** `check_password` verifica la contraseña también cuando la cuenta está bloqueada, con el
  mismo coste, y responde `credenciales no válidas`. Registra `account.login_blocked`. Se actualiza
  `test_failed_logins_lock_the_account_until_the_lockout_expires`, que esperaba el mensaje de bloqueo,
  y se añade `test_locked_account_answers_exactly_like_an_unknown_user`. Las dos fallan con el código
  anterior y pasan con el corregido. Resultado: 214 casos pasan; ruff y mypy sin errores. `docs/seguridad.md` y `docs/IMPLEMENTATION_STATUS.md` se ajustan
  a lo que el código hace.

El resto de hallazgos se planifica en la sección 13.

## 13. Plan de corrección por etapas

| Etapa | Objetivo | Entregables | Criterio de aceptación |
|---|---|---|---|
| 2 Arquitectura | Decidir el modelo de contexto | Modelo de actor y de ámbito; decisión sobre el bus de eventos; reglas de capas | `arquitectura.md` actualizado (P-09). Prueba que verifica las dependencias entre paquetes (P-16). |
| 3 Kernel | Composición sin acoplamiento | Módulo `bootstrap` con factorías; accesores tipados (P-12, P-08) | `kernel.start` no importa subsistemas concretos. Las pruebas de kernel pasan sin cambios. |
| 4 Multiempresa | Aislamiento de datos (prioridad) | Tablas de empresas y pertenencias; empresa obligatoria en datos de empresa; repositorios que filtran | Pruebas de aislamiento cruzado: una cuenta de A no lee ni escribe datos de B. |
| 5 Aplicaciones y entornos | Modelo por empresa | Aplicaciones, entornos y configuración por entorno | Pruebas de herencia y de alcance por entorno. |
| 6 Versiones | Versiones por ámbito | Carga y reversión por entorno; compatibilidad | Pruebas de carga con dependencias incompatibles. |
| 7 Módulos y plugins | Un solo flujo de estado (P-10, P-18) | Gestor común de habilitación; permisos aplicados al ejecutar | Sin duplicación de reglas. Opciones de plugins protegidas. |
| 8 Seguridad y RBAC | Autorización en los casos de uso (P-01, P-02, P-04, P-05) | Actor obligatorio; permisos con ámbito; alta de editores con permiso y auditoría | Pruebas de escalada, sesión caducada, permiso caducado y alta de editor sin permiso. |
| 9 Persistencia | Atomicidad y copias (P-03, P-06, P-07) | Auditoría en la misma transacción; copia y restauración de la base con SHA-256 y autorización; WAL; política de hilos | Pruebas de fallo a mitad de transacción y de restauración. |
| 10 Auditoría | Registro verificable (R-03) | Encadenado con hash previo; verificador | Una alteración de un evento se detecta. |
| 11 Automatización | Acciones con aprobación humana | Tareas con estados; aprobación para operaciones críticas | Ninguna operación crítica se ejecuta sin aprobación registrada. |
| 12 Interfaces | Terminal sin lógica de flujo (P-15) | Casos de uso compartidos; aplicación de escritorio; lanzador probado | Las dos interfaces llaman a los mismos casos de uso. |
| 13 Informes | Reportes empresariales | HTML, CSV, JSON y TXT; PDF cuando se decida la dependencia | Informes reproducibles a partir de la auditoría. |
| 14 Diagnósticos | Salud por subsistema | Estado por servicio; comprobación de integridad | Un servicio roto aparece como degradado. |
| 15 Pruebas | Cobertura medida (P-16, P-13) | `pytest-cov`; helpers compartidos; prueba del lanzador en Windows | Cobertura medida y publicada. |
| 16 Documentación | Estado veraz | Todos los documentos | Revisión de cada afirmación contra el código (R-11). |

## 14. Prioridades

1. **P0, ahora:** P-02 (corregido en esta etapa); P-05 (alta de editores sin permiso ni auditoría).
2. **P0, diseño en la etapa 2 e implementación en la 8:** P-01 (autorización en los servicios).
3. **P1, etapa 4:** multiempresa, con empresa obligatoria en los datos. Sin este modelo no se
   deben añadir más tablas de datos de cliente.
4. **P1, etapa 9:** P-03 (atomicidad) y P-06 (copia de la base).
5. **P1, etapa 8:** P-04 (bootstrap del primer administrador).
6. **P2:** P-07 y P-08 (hilos y eventos), P-09 (documentación), P-10 a P-12 (duplicación y
   composición), P-14 (configuración), P-15 (terminal), P-16 (pruebas de arquitectura y cobertura),
   P-18 (tamaño de `plugins/manager.py`).
7. **P3:** P-13 (helper de pruebas), P-17 (dependencias fijadas), P-19 (lanzador en Windows).

## 15. Decisiones pendientes

Ninguna bloquea el trabajo. Cada una tiene una propuesta por defecto:

- **Primer administrador (P-04).** Propuesta: código de instalación de un solo uso que se muestra
  en la consola local. Alternativa: aceptar el riesgo documentado.
- **Bus de eventos (P-08).** Propuesta: conectarlo a la auditoría en la etapa 3 y retirarlo solo si
  no tiene consumidores al final de la etapa 12.
- **Informes PDF.** Propuesta: HTML imprimible en la etapa 13 y PDF cuando se apruebe una
  dependencia.
- **Aplicación de escritorio.** Propuesta: la biblioteca estándar (`tkinter`) para no añadir
  dependencias; se decide en la etapa 12.
- **Borrado de plugins de editores revocados.** Propuesta: conservar el registro; no borrar datos
  de auditoría.
