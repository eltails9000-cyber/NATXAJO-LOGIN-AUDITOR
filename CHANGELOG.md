# CHANGELOG

## [Sin publicar]

- Etapa 4.1: endurecimiento posterior a la fusión de la etapa 4 (rama
  `etapa-4-1-endurecimiento`).
  - Sesiones: visitantes anónimos (256) y sesiones autenticadas (64) tienen límites separados. Con
    el grupo lleno se rechaza la entrada (503) en lugar de expulsar a otra sesión. Un límite por
    cuenta se audita como `session.limit_reached`.
  - Entrada: las credenciales incorrectas y el límite por cuenta dan la misma respuesta (401
    `credenciales`). La instalación pendiente sigue en 409.
  - Guardián: `operation.denied`, `operation.executed` y `operation.failed`, sin contraseñas ni
    valores; solo el tipo de error. Un fallo al auditar no oculta el resultado de la operación.
  - Limpieza: un archivo que no se puede borrar no detiene la limpieza ni cuenta como eliminado.
    Evento `maintenance.cleanup_applied` con `removed` y `failed`.
  - Diagnóstico y copias: cada comprobación se aísla y su fallo aparece como error. Una copia que
    falla al crearse no deja archivos a medias; un manifiesto o una copia ilegibles son un problema
    devuelto, no una excepción.
  - Plugins: una revisión solo vale para el SHA-256, el editor y la versión revisados (migración
    12). Las aprobaciones anteriores no autorizan nada: hay que volver a revisar los plugins de
    terceros. Evento `plugin.reviewed`.
  - Auditoría inmutable: los eventos y las revisiones no se modifican ni se borran (disparadores,
    migración 12).
  - Informes firmados con Ed25519 (`firma_informes.clave`, archivo `.firma.json`). Los informes
    anteriores quedan sin firma y se verifican solo por huella.
  - Validación de identificadores con `fullmatch`: un salto de línea final ya no pasa.
  - Panel del sistema: solo la plataforma ve el detalle técnico; las empresas ven la versión.
  - Eventos fallidos: reencolado controlado (`requeue_event`, `requeue_dead`), solo por la API de
    la plataforma, con confirmación y reautenticación. Evento `event.requeued`. Migración 13
    (contadores de reencolado). Solo API: la terminal y la interfaz no lo ofrecen.
  - Cambios incompatibles:
    - `PluginManager.record_review` exige `reviewed_sha256` y acepta `confirmed`.
    - `MaintenanceService.apply_cleanup` devuelve `planeados`, `eliminados`, `fallidos` y
      `detalle_fallidos`.
    - `EventOutbox.requeue_dead` exige `audit` y `actor`.
    - `rollback_migrations` exige `discard_data=True` para revertir una migración con filas
      protegidas (migraciones 10, 11 y 12).
    - La base de datos llega a la versión 13.
    - `ReadModels.system_info` exige el token de la sesión.
    - `ReportService` recibe un firmante.

- Interfaz gráfica local (`python main.py --gui`): panel, auditoría, usuarios, sesiones,
  plugins, módulos, reportes, eventos, seguridad, mantenimiento y configuración. Servidor en
  127.0.0.1 con biblioteca estándar, sin CDN ni dependencias nuevas. Operaciones existentes
  con su guardián, confirmación y reautenticación. Preferencias en `config/interfaz.json`.
  Detalle en `docs/INTERFAZ_GRAFICA.md`.
  - Sesiones: listado de solo lectura sin fichas ni huellas (`SessionStore.list_live`).
  - Límite de sesiones simultáneas: error propio (`SessionLimitError`), distinguible de las
    credenciales incorrectas.
  - Empaquetado: `static/*` incluido en el paquete.
- Etapa 4: motor de auditoría sin conexión, informes, mantenimiento y terminal (rama
  `etapa-4-auditoria-informes-mantenimiento`).
  - Motor (`auditing/`): 17 reglas de autenticación configurables dentro de límites fijos, perfiles
    `completo` y `critico`, huella canónica de la configuración, validación de resultados y
    evaluaciones inmutables. Migración 10, reversible.
  - Informes (`reporting/`): JSON, CSV, HTML y TXT. Exportación atómica registrada en la misma
    transacción, verificación de cinco estados y evento de fallo con motivo recortado.
  - Mantenimiento (`maintenance/`): diagnóstico de ocho comprobaciones y limpieza de temporales
    `*.tmp` con plan previo, confirmación y reautenticación. Nunca sigue enlaces.
  - Plugins (fase 6): cuarentena por versión, actualización a una versión nueva del mismo editor y
    reversión a la versión anterior. Sin ejecución de plugins. Migración 11, reversible, con
    `plugin_quarantine` y `plugin_history`. Detalle en `docs/PLUGINS_CICLO.md`.
    - Cuarentena: bloquea la habilitación, deshabilita los dependientes habilitados y se libera con
      confirmación y reautenticación.
    - Actualización: exige plugin deshabilitado, versión estrictamente mayor, mismo editor y copia
      verificada. Conserva una versión anterior; la siguiente actualización retira la anterior.
    - Reversión: intercambia la versión activa con la anterior. Verifica la copia antes de cambiar.
    - Permisos nuevos: `plugins:nucleo:estado:leer`, `plugins:nucleo:cuarentena:escribir`,
      `plugins:nucleo:cuarentena:administrar` (crítico) y `plugins:nucleo:version:administrar`
      (crítico).
    - Pruebas: 32 en `test_plugins_ciclo.py`, 8 en `test_terminal_plugins.py` y 1 en
      `test_migracion_11.py`.
  - Terminal: opciones 20 a 33. Tipos compartidos en `console.py` y acciones por áreas en
    `operaciones.py` y `operaciones_plugins.py`. Las operaciones con guardián no se registran dos
    veces.
  - Eventos: `audit.run_recorded`, `report.exported`, `report.failed`, `maintenance.cleanup_applied`,
    `plugin.quarantined`, `plugin.quarantine_released`, `plugin.updated` y `plugin.rolled_back`. El
    catálogo pasa de 35 a 43 tipos.
  - Permisos nuevos: auditoría (evaluar y leer), informes (exportar y leer), diagnóstico y limpieza
    (solo plataforma; la limpieza es crítica).
  - Lanzador: detecta Python 3.11 real, ignora los alias de la Microsoft Store, comprueba `main.py`
    y da errores claros. Escrito con BOM UTF-8. No se ha ejecutado en Windows.
  - Cambios de expectativa en pruebas existentes: la migración 10 y los tres servicios nuevos en
    `test_storage.py`, `test_migrations_stage2.py` y `test_kernel_characterization.py`.
  - Pendiente: pruebas activas de auditoría, instalación y habilitación de plugins desde la terminal,
    restauración desde la terminal, ejecución de plugins e interfaz de escritorio.
  - Pruebas: 498 recogidas, 497 aprobadas, 0 fallidas y 1 omitida (lanzador sin PowerShell).

- Etapa 3, fase A (P-05): editores de confianza protegidos en el servicio y en la base.
  - Dar de alta (`register_publisher`), revocar (`revoke_publisher`) y revisar un plugin de
    terceros (`record_review`) exigen sesión, un permiso crítico, ámbito de plataforma,
    confirmación y reautenticación. El revisor y quien revoca son la cuenta de la sesión.
  - Auditoría: `plugin.publisher_registered` (nuevo), `plugin.publisher_revoked` (con el usuario) y
    `plugin.reviewed`, en la misma transacción que el cambio.
  - Migración 9, reversible: la clave de un editor no cambia, un editor revocado no vuelve a estar
    activo y los editores no se borran.
  - Cambio incompatible: `revoke_publisher` y `record_review` reciben el token de sesión. Las altas
    ya no existen como método de `TrustStore`.
  - Pruebas: 18 nuevas en `tests/test_editores_confianza.py`.

- Etapa 3, fase C (P-17): dependencias de desarrollo con rangos probados y bloqueo reproducible.
  - Rangos: pytest `>=9.1,<10`, ruff `>=0.16,<0.17`, mypy `>=2.3,<3`. Python 3.11 mínimo.
  - `requirements-dev.lock` fija las versiones y sus dependencias. Sin hashes: pendiente de
    generar con acceso al índice.
  - Pruebas: 5 nuevas en `tests/test_dependencias.py`. Procedimiento en `docs/DEPENDENCIAS.md`.

- Etapa 3, fase D (kernel): composición sin acoplamiento. Sin cambio de comportamiento.
  - Pruebas de caracterización del orden de arranque y de parada (`tests/test_kernel_characterization.py`).
  - `kernel/composition.py` construye los servicios. `Kernel.start` ya no importa subsistemas.
  - `ServiceKey[T]`: registro y consulta tipados, con comprobación de clase. Los accesores del
    kernel no usan `cast`. `register` y `get` por nombre se conservan.
  - Retirado `kernel.events` (`kernel/event_bus.py`). El registro de arranque y de parada sigue en
    la auditoría, a través del outbox.

- Etapa 3, fase E (arquitectura): dependencias indebidas corregidas.
  - `security/permissions.py` pasa a `core/permissions.py`. `SessionError` pasa a
    `core/exceptions.py`. `PLATFORM_COMPANY`, `SCOPE_DENIED` y `APPROVE_PERMISSION` pasan a
    `core/contracts.py`. `kernel_matches` pasa a `core/validation.py`.
  - La terminal ya no importa `security`. `Installer` expone `code_ttl` y `max_code_attempts`.
  - Cambio de rutas de importación: quien importe estos símbolos desde su módulo anterior debe
    cambiar la importación.
  - `tests/test_arquitectura.py`: 16 pruebas AST sobre capas, subsistemas en la composición,
    ciclos, `cast`, ejecución dinámica en `modules/` y `plugins/`, hashlib y la tabla de
    `docs/arquitectura.md`.

- Auditoría posterior a la etapa 2 (`docs/AUDITORIA_ETAPA_2.md`):
  - Corregido: el guardián no comprobaba el ámbito de empresa cuando una operación no indicaba
    empresa. Ahora una operación sin empresa es de plataforma.
  - Corregido: el contador de fallos y el bloqueo se deciden dentro de la transacción de escritura.
    Un acierto ya no salta un bloqueo fijado durante la verificación.
  - Corregido: aprobar, rechazar y revocar un permiso temporal es una transición condicionada. Una
    solicitud no puede resolverse dos veces.
  - Corregido: el límite de sesiones simultáneas se comprueba dentro de la transacción de escritura.
  - Corregido: la comprobación de entrega del bus se hace dentro de la transacción del consumidor.
  - Nuevo: un consumidor se ejecuta bajo un autorizador de SQLite. No puede escribir en tablas de la
    plataforma, ni editar o borrar la auditoría, ni cambiar el esquema.
  - Pruebas: 279 casos (262 existentes sin cambios y 17 nuevas).
  - Pendiente: la API interna del núcleo sin token (P-01), la espera entre reintentos del bus y la
    comprobación de la versión de SQLite antes de revertir migraciones.

- Etapa 2 de la especificación, dentro de la fase 7:
  - Multiempresa: tabla `companies` con la empresa `plataforma`. Cada cuenta tiene `company_id`,
    fijado al crearla y protegido por disparadores. El ámbito se comprueba en el guardián, en los
    permisos temporales, en la auditoría y en la terminal.
  - Terminal: opciones 18 (crear empresa) y 19 (listar empresas), solo para la plataforma. La
    auditoría y las solicitudes de permisos se filtran por empresa.
  - Instalador del primer administrador con código de un solo uso: hash PBKDF2, caducidad de 30
    minutos, cinco intentos y cierre permanente por disparador.
  - Bus de eventos: catálogo tipado de 34 eventos, outbox transaccional, consumidores idempotentes,
    reintentos, cola de fallidos y reenvío al arrancar. La auditoría es un consumidor. Las categorías
    `operativo` y `seguridad` se guardan por separado.
  - Migraciones 6 a 8, reversibles. Antes de migrar una base existente se guarda una copia en
    `storage/migraciones/`. Plan y resultados en `docs/MIGRACION_ETAPA_2.md`.
  - Corrección de la etapa 2: los cambios de estado, contraseña y roles de cuentas, y las
    reautenticaciones y caducidades de sesión, se escriben y auditan en una transacción.
  - 262 casos de prueba automatizados (214 existentes y 48 nuevas), con ruff y mypy en modo estricto
    sin errores.
- Cambio incompatible: `SecurityService.bootstrap_administrator` se elimina. El primer administrador
  se crea con el instalador. `AuditLog.record` solo acepta eventos del catálogo y sus claves
  declaradas; un nombre desconocido se rechaza.
- Corrección de seguridad: durante un bloqueo de cuenta, la respuesta ya no revela que la cuenta
  existe. Los intentos bloqueados quedan en la auditoría como `account.login_blocked`.
- Auditoría de arquitectura en `docs/CLAUDE_ARCHITECTURE_AUDIT.md`, con plan de corrección por etapas.
- Fase 7 (parcial): seguridad y control de acceso. Cuentas con contraseñas PBKDF2-HMAC-SHA256 y
  bloqueo tras cinco fallos; roles integrados con separación de funciones entre `operador` y
  `auditor`, herencia de hasta 5 niveles y anti-escalada; sesiones con caducidad por inactividad (15
  minutos) y absoluta (8 horas), límite de 3 sesiones por cuenta y reautenticación; permisos
  temporales aprobados por otra cuenta; guardián de operaciones críticas que registra denegaciones y
  ejecuciones; protección del último administrador. Terminal: creación del primer administrador,
  inicio de sesión, menú filtrado por permisos y opciones 14 a 17.
- Fase 7, pendiente: revocar permisos, deshabilitar cuentas y cambiar roles o contraseñas solo desde
  la API; recuperación de acceso; cifrado de la base de datos; integridad de la auditoría.
- Migración 5: tablas `accounts`, `roles`, `role_grants`, `role_parents`, `account_roles`,
  `permission_grants` y `sessions`.
- Fase 6 (parcial): plugins como paquetes firmados. Firma Ed25519 en Python puro, sin
  dependencias, comprobada con el RFC 8032, `cryptography` y OpenSSL. Integridad por SHA-256 de
  cada archivo, editores de confianza con revocación, catálogo local con índice verificado,
  revisión registrada para editores de terceros, habilitación con dependencias, revocación en
  cascada y auditoría. Los plugins aún no se ejecutan ni se gestionan desde la terminal.
- Cambio incompatible: los permisos de los manifiestos usan el formato
  `subsistema:modulo:recurso:accion` (antes `auditoria.leer`). Los módulos que usaban el formato
  anterior deben actualizarse.
- Migración 4: tablas `plugin_publishers`, `plugin_installs` y `plugin_reviews`.
- Validadores compartidos (`core/validation.py`) y grafo de dependencias genérico
  (`core/graph.py`). `modules/permissions.py` se sustituye por `security/permissions.py`.
- `docs/roadmap.md` se sustituye por `docs/IMPLEMENTATION_STATUS.md`, con estados definidos.
- Fase 5: sistema de módulos declarativos (`modules/<id>/module.json`) con permisos de catálogo
  cerrado, descubrimiento tolerante a fallos, grafo de dependencias con detección de ciclos,
  habilitación y deshabilitación protegidas, estado persistente auditado y diagnóstico.
- Las versiones pueden requerir módulos habilitados. Antes, cualquier dependencia bloqueaba la
  carga sin posibilidad de resolverla.
- Terminal: opciones 10 a 13 para módulos.
- Migración 3: tabla `module_states`.
- 213 casos de prueba automatizados, con ruff y mypy en modo estricto sin errores.

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
