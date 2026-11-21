# CHANGELOG

## [Sin publicar]

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
