# Estado de implementación

Este documento sustituye a `docs/roadmap.md`. Describe lo que existe en el código, no lo que
aparece en el documento maestro.

## Etapa de especificación y fase del repositorio

- **Etapa de especificación:** 2 (arquitectura). Se aplicaron las tres decisiones aprobadas: modelo
  multiempresa con `company_id` fijado por el servidor, instalador del primer administrador con
  código de un solo uso, y bus de eventos integrado con la auditoría. La etapa 1 (auditoría) está
  en `docs/CLAUDE_ARCHITECTURE_AUDIT.md`. Las etapas 3 a 16 no se han iniciado.
- **Fase del repositorio:** 7 (seguridad y RBAC), en estado parcial. La etapa 2 se integra en esta
  fase. Las fases 3 a 6 no cambian de estado en esta etapa.

## Estados

- **VERIFICADO**: implementado y cubierto por pruebas automatizadas que pasan.
- **IMPLEMENTADO**: el código existe, pero no todas sus partes tienen pruebas o no se ha probado en
  el entorno objetivo (por ejemplo, Windows).
- **PARCIAL**: una parte está implementada y verificada; el resto de la fase figura en
  "pendiente".
- **PENDIENTE**: no existe en el código. No se declara como disponible.

## Resumen por fase

| Fase | Contenido | Estado |
|---|---|---|
| 1 | Inspección, diagnóstico, arquitectura y documentación | VERIFICADO (documentación en `docs/`) |
| 2 | Núcleo, ciclo de vida, contenedor de servicios, bus de eventos | VERIFICADO |
| 3 | Configuración, almacenamiento, migraciones, copias | PARCIAL |
| 4 | Gestor de versiones y cargador manual | PARCIAL |
| 5 | Sistema de módulos y dependencias | VERIFICADO (los módulos no ejecutan código) |
| 6 | Plugins: firma, integridad, editores, catálogo, revisión y ciclo de vida | PARCIAL |
| 7 | Seguridad, RBAC, sesiones, guardián, multiempresa, instalador y bus de eventos (etapa 2) | PARCIAL |
| 8 | Motor de automatización | PENDIENTE |
| 9 | Motor de auditoría defensiva | PENDIENTE |
| 10 | Aplicación de escritorio y terminal avanzada | PENDIENTE |
| 11 | Diagnósticos, informes y analítica | PENDIENTE |
| 12 | Mantenimiento, actualizaciones y recuperación | PENDIENTE |
| 13 | Pruebas integrales y distribución | PENDIENTE |

Pruebas automatizadas: 279 casos (214 de la etapa 1, de las que 4 cambiaron de procedimiento o de
expectativa; 48 nuevas de la etapa 2; y 17 de la auditoría posterior a la etapa 2, en
`tests/test_auditoria_postimplementacion.py`), con ruff y mypy en modo estricto sin errores.
Verificadas en Linux. Windows no está verificado (ver `docs/PRUEBAS_WINDOWS.md`).

## Fase 3: configuración y almacenamiento (PARCIAL)

- **Verificado:** configuración con esquema estricto, historial y restauración solo con
  autorización; base SQLite con migraciones transaccionales; auditoría; copias con SHA-256.
- **Pendiente:** perfiles predefinidos y personalizados, herencia y overrides, importación y
  exportación, comparación, copias incrementales, cifrado y control de acceso sobre la base de
  datos.
- **Diagnóstico:** el servicio de configuración no está conectado a la terminal, y varias claves del
  esquema (`logging.*`, `auditing.enabled`, `general.theme`, `general.locale`, `general.level`) no
  las usa ningún componente.

## Fase 4: versiones (PARCIAL)

- **Verificado:** canales, manifiestos validados, registro desde `versions/`, compatibilidad con el
  núcleo, carga manual, cambio, reversión e historial.
- **Pendiente:** ramas, etiquetas, snapshots, canales personalizados, comparación detallada,
  clonación, exportación, archivado, editor avanzado y asistente de creación.

## Fase 5: módulos (VERIFICADO)

- **Verificado:** manifiestos `modules/<id>/module.json` con permisos de catálogo, descubrimiento
  que aísla los módulos rotos, dependencias con detección de ausencias y ciclos, habilitación que
  activa antes las dependencias, deshabilitación protegida, estado persistente auditado y
  diagnóstico.
- **Pendiente:** ejecución de módulos (sin fase asignada), aplicación de los permisos declarados a
  la ejecución de módulos (depende de que exista ejecución), actualización y desinstalación.

## Fase 6: plugins (PARCIAL)

### Verificado

- **Criptografía:** Ed25519 en Python puro (`core/ed25519.py`), sin dependencias externas. Se
  comprueba con el vector de prueba 1 del RFC 8032, con firmas idénticas a las de la biblioteca
  `cryptography` en 40 casos, y con una firma generada por OpenSSL. Limitación documentada: no es
  de tiempo constante. Sirve para verificar datos públicos, no para firmar secretos.
- **Paquete:** carpeta con `plugin.json`, `integrity.json` (SHA-256 de cada archivo) y
  `signature.json` (firma Ed25519 de `integrity.json`). Como `integrity.json` incluye el hash de
  `plugin.json`, la firma protege también el manifiesto. Se rechazan enlaces simbólicos, archivos
  no declarados, archivos ausentes y archivos alterados.
- **Verificación antes de aceptar:** firma, editor registrado y no revocado, integridad,
  manifiesto, versión de API soportada y compatibilidad con el núcleo.
- **Editores de confianza:** clave pública Ed25519, nivel de confianza (`official`, `verified`,
  `third_party`, `revoked`).
- **Catálogo local:** `index.json` con el hash de cada paquete. Se comprueba que el índice
  coincide con el paquete y que la entrada corresponde a la versión pedida.
- **Revisión:** inventario de archivos (los ejecutables se señalan) y registro de decisiones con
  historial. Un plugin de editor `third_party` solo se habilita con una revisión aprobada.
- **Ciclo de vida:** instalar (deshabilitado), habilitar (habilita antes sus dependencias y
  vuelve a verificar la copia almacenada), deshabilitar (bloqueado si otro habilitado lo
  requiere), desinstalar (bloqueado si está habilitado o si otro instalado lo requiere).
- **Revocación:** revocar un editor deshabilita sus plugins y los que dependen de ellos,
  transitivamente. Un editor revocado no vuelve a estar activo, ni siquiera con SQL (migración 9).
- **Confianza protegida (P-05):** alta, revocación y revisión solo con la cuenta de la plataforma,
  con permiso crítico, confirmación y reautenticación. Pruebas en
  `tests/test_editores_confianza.py`.
- **Auditoría:** instalaciones, rechazos, habilitaciones, deshabilitaciones, desinstalaciones,
  revisiones y revocaciones quedan en `audit_events`.
- **Persistencia:** el estado sobrevive a un reinicio del núcleo.

### Pendiente

- **Ejecución de plugins.** No se ejecutan. Habilitar solo registra el estado. Hace falta un
  mecanismo de procesos aislados que aún no existe.
- **Repositorios remotos.** Solo hay catálogo local. No se implementa HTTPS.
- **Actualización de versiones.** Un plugin tiene una única versión instalada. Para cambiarla hay
  que desinstalarla primero.
- **Terminal.** No hay opciones de menú para plugins. Se gestionan desde la API del núcleo
  (`kernel.plugins`). El control de acceso de la fase 7 ya existe, así que las opciones pueden
  añadirse protegidas por permiso.
- **Revisión automática.** El inventario clasifica por extensión. No detecta código malicioso ni
  sustituye la revisión humana.

## Fase 7: seguridad y RBAC (PARCIAL)

### Verificado

- **Cuentas y contraseñas:** PBKDF2-HMAC-SHA256 con sal de 16 bytes, política de contraseñas,
  bloqueo tras 5 fallos durante 15 minutos. El mensaje de error es idéntico para usuario inexistente,
  contraseña incorrecta y cuenta bloqueada (corregido en la etapa 1).
- **Sesiones:** ficha de 256 bits guardada como hash, caducidad por inactividad (15 minutos) y
  absoluta (8 horas), límite de 3 sesiones por cuenta, cierre y reautenticación.
- **Roles:** builtin `administrador`, `operador` y `auditor`; separación de funciones entre
  `operador` y `auditor`; herencia de hasta 5 niveles; un rol nuevo no puede conceder más de lo que
  posee quien lo crea.
- **Último administrador:** no puede deshabilitarse ni perder el rol de administrador.
- **Permisos temporales:** solicitud de 1 a 240 minutos, aprobación por otra cuenta que posea el
  permiso concedido, sin autoaprobación, rechazo, revocación y caducidad.
- **Guardián de operaciones:** comprueba sesión, permiso, confirmación y reautenticación reciente
  para las operaciones críticas; registra denegaciones y ejecuciones en la auditoría.
- **Terminal:** instalación del primer administrador con código, inicio de sesión con tres intentos,
  caducidad que vuelve a la pantalla de inicio, menú filtrado por permisos y por empresa,
  confirmación y reautenticación para las opciones críticas. Opciones 14 a 19: crear cuenta,
  solicitar permiso temporal, aprobar o rechazar permiso temporal, reautenticar, crear empresa y
  listar empresas.
- **Migración 5:** tablas `accounts`, `roles`, `role_grants`, `role_parents`, `account_roles`,
  `permission_grants` y `sessions`. Migraciones 6 a 8: empresas, instalación y bus de eventos (ver
  la etapa 2 más abajo).
- **Pruebas:** 39 casos en `tests/test_security.py`, más las pruebas de terminal.

### Etapa 2 de la especificación (VERIFICADO)

- **Multiempresa.** Tabla `companies` con la empresa reservada `plataforma`. Cada cuenta tiene
  `company_id`, fijado al crearla. Un disparador impide cambiarlo y no permite borrar empresas con
  cuentas ni la plataforma. El actor de cada operación sale de la cuenta en la base de datos, nunca
  de la entrada del usuario. Una cuenta de empresa solo actúa sobre su empresa; la plataforma actúa
  sobre todas.
- **Ámbito en el guardián y en el almacén.** `OperationGuard` comprueba el ámbito antes de pedir
  confirmación. Las solicitudes de permisos temporales, sus aprobaciones, rechazos y revocaciones
  comprueban el ámbito de la cuenta afectada. En la terminal, una cuenta inexistente y una ajena dan
  el mismo mensaje fuera de la plataforma. La API sigue distinguiendo los dos casos.
- **Permisos administrativos.** Crear empresas exige `seguridad:nucleo:empresa:administrar`, es
  crítico y solo lo ejecuta la plataforma. Una cuenta de empresa crea cuentas solo en su empresa.
- **Instalador.** Código de 128 bits, guardado solo como hash PBKDF2, válido 30 minutos y con cinco
  intentos fallidos como máximo. Un solo uso. Al completarse, la instalación queda cerrada por un
  disparador. Mientras no se completa, no se pueden crear cuentas.
- **Bus de eventos.** Catálogo cerrado de 34 tipos, cada uno con sus claves obligatorias y
  opcionales. Outbox transaccional: el evento se guarda en la misma transacción que el cambio y se
  entrega tras confirmarla. Consumidores idempotentes con registro de entregas, reintentos, cola de
  fallidos y reenvío al arrancar. La auditoría es un consumidor más.
- **Categorías.** `operativo` (cambios de la plataforma) y `seguridad` (cuentas, sesiones, permisos,
  operaciones e instalación). La auditoría se puede filtrar por categoría y por empresa.
- **Migraciones 6 a 8.** Reversibles. Copia previa de la base antes de migrar una base existente.
  Plan y resultados en `docs/MIGRACION_ETAPA_2.md`.
- **Verificación.** Pruebas de aislamiento, instalación, permisos administrativos, bus de eventos y
  migraciones (48 casos). Además, seis fallos introducidos a propósito en una copia de trabajo; cinco
  los detectaron las pruebas de inmediato y el sexto, la falta de registro de entregas, llevó a
  añadir una prueba que ahora lo detecta.

### Pendiente

- **Gestión desde la terminal.** Revocar permisos, deshabilitar cuentas, cambiar roles y cambiar
  contraseñas solo están en la API (`kernel.security`).
- **Recuperación de acceso.** No hay recuperación de contraseñas, borrado de cuentas ni desbloqueo
  manual.
- **Integridad de la auditoría.** Los eventos no están encadenados ni firmados.
- **Cifrado.** La base de datos y las copias están en texto plano; solo las contraseñas van como
  hash.
- **Aplicación de permisos a módulos y plugins.** Los permisos que declaran se validan en el formato
  `subsistema:modulo:recurso:accion`, pero no se aplican porque no existe ejecución de módulos ni
  plugins.
- **Multiempresa (parcial).** Las empresas existen, pero no hay aplicaciones ni entornos. Las
  operaciones de instalación (versiones, módulos, plugins, copias) son de la plataforma. Quedan
  pendientes la desactivación de empresas y los roles propios de cada empresa.
- **Terminal de eventos fallidos.** La cola de eventos fallidos se consulta por API, pero la terminal
  no la muestra ni la reencola.

Detalle de límites y de qué protege cada control: `docs/seguridad.md`.

## Auditoría posterior a la etapa 2

`docs/AUDITORIA_ETAPA_2.md` revisa el commit `9a371c7`. Corregidos siete defectos con pruebas de
regresión: el guardián sin empresa (A-01), el contador de fallos y el bloqueo bajo concurrencia
(A-02, A-03), la doble resolución de permisos temporales (A-04), el límite de sesiones (A-05), la
doble entrega del bus (A-06) y los permisos de los consumidores (A-07). Abierto: P-01, la API
interna del núcleo sin token. Riesgo aceptado hasta la etapa 8, y condición para ejecutar módulos o
plugins. Windows no está verificado.

Etapa 3, fase A: P-05 (editores de confianza sin control) estaba fuera de la auditoría anterior. Se
corrige con la puerta de operaciones, transacciones, auditoría y la migración 9. Ver
`docs/AUDITORIA_ETAPA_2.md`, sección 3.1.

## Auditoría de arquitectura (etapa 1)

`docs/CLAUDE_ARCHITECTURE_AUDIT.md` evalúa el commit `16cbcf9` y propone el plan por etapas.
Hallazgos prioritarios:

- **P0:** la autorización solo se aplica en la terminal. Los servicios (`kernel.security`,
  `kernel.plugins`, `kernel.modules`, `kernel.versions`) no comprueban permisos.
- **P0:** el registro de editores de confianza no exige permiso ni queda en la auditoría.
- **P1:** los cambios de estado de cuentas y sesiones no van en la misma transacción que su
  auditoría.
- **P1:** la base de datos no tiene copia de seguridad desde la aplicación.
- **Corregido:** durante un bloqueo, la respuesta revelaba que la cuenta existía.
- **Corregido en la etapa 2:** P-04, el primer administrador se creaba sin código; ahora lo crea el
  instalador. Los cambios de estado, contraseña y roles de cuentas, y las reautenticaciones y
  caducidades de sesión, se escriben y auditan en una transacción.
- **Abierto:** P-01, la API del kernel sin token sigue siendo de confianza. Previsto para la etapa 8.

## Otros pendientes

- Carpetas `powershell/` y `scripts/`: no se crean vacías. Se añadirán con su contenido.
- `launcher.ps1` no se ha probado en Windows. No hay PowerShell en el entorno de desarrollo.
- Instalación de dependencias (`pip install -e .[dev]`): no comprobada en este entorno.

## Cómo añadir una fase

1. Escribir las pruebas primero, en `tests/`.
2. Implementar solo lo necesario para que pasen.
3. Actualizar esta tabla, `CHANGELOG.md` y la documentación afectada.
4. No marcar nada como VERIFICADO si sus pruebas no pasan.
