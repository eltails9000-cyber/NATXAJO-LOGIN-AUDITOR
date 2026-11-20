# CHANGELOG

## [Sin publicar]

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
