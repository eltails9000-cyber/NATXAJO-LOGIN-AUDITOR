# Plan de migración: etapa 2 (multiempresa, instalación y bus de eventos)

Etapa 2 de la especificación corporativa (fase 7 del repositorio, commit base `1bad72b`).
Este documento se escribió antes de modificar el código. Las secciones 5 y 6 se completaron después
con los resultados verificados.

## 1. Inspección

### 1.1 Datos y repositorios

| Dato | Tabla o archivo | Naturaleza | Repositorio o caso de uso |
|---|---|---|---|
| Cuentas | `accounts` | Empresarial: pertenece a una empresa | `AccountStore` |
| Roles de cuenta | `account_roles` | Empresarial (a través de la cuenta) | `AccountStore.set_roles` |
| Permisos temporales | `permission_grants` | Empresarial (a través de la cuenta) | `GrantStore` (solicitar, aprobar, rechazar, revocar, listar) |
| Sesiones | `sessions` | Empresarial (a través de la cuenta) | `SessionStore` |
| Auditoría | `audit_events` | Mixta: eventos de empresa y de instalación | `AuditLog.list_events` sin filtro |
| Catálogo de roles y permisos | `roles`, `role_grants`, `role_parents` | Plataforma (global) | `RoleStore` |
| Versiones activas, módulos, plugins, editores | `platform_metadata`, `module_states`, `plugin_*` | Plataforma (instalación) | `VersionManager`, `ModuleManager`, `PluginManager` |
| Configuración y copias | `config/`, `storage/backups/` | Plataforma (archivos) | `ConfigurationManager`, `BackupManager` |

No existe todavía ninguna tabla de datos de cliente (aplicaciones, entornos, auditorías).
La multiempresa se demuestra sobre cuentas, permisos temporales, sesiones y auditoría.

### 1.2 Rutas que pueden omitir el ámbito de empresa

| Ruta | Problema | Corrección prevista |
|---|---|---|
| Terminal, opción 7 (eventos de auditoría) | Lista todos los eventos, de cualquier empresa | Filtro por empresa del actor; la plataforma ve todo |
| Terminal, opción 14 (crear cuenta) | Crea la cuenta en la plataforma sin preguntar | Empresa del actor; la plataforma puede elegir empresa |
| Terminal, opción 15 (solicitar permiso temporal) | Permite solicitar permisos para cualquier cuenta | Comprobación de ámbito sobre la cuenta objetivo |
| Terminal, opción 16 (resolver permisos) | `list_grants()` muestra solicitudes de todas las empresas | Lista filtrada; aprobar o rechazar comprueba el ámbito |
| `AccountStore.accounts()` | Lista todas las cuentas | Versión por empresa |
| `GrantStore.list_grants()` | Lista todas las solicitudes | Versión por empresa |
| `AuditLog.list_events()` | Sin filtro | Filtro por empresa y por categoría |
| Operaciones de instalación (versiones, módulos, plugins, copias) | Accesibles a cualquier cuenta con permiso | Requieren el ámbito de la plataforma |
| API del kernel sin token | Llamadas de confianza sin guardián | Se mantienen como API interna; las interfaces no las usan (limitación documentada) |

### 1.3 Bus de eventos y auditoría actuales

- **`EventBus`** (`kernel/event_bus.py`): publicación y suscripción en memoria, sin contrato de
  datos, sin persistencia y sin manejo de fallos. Solo lo usa el kernel para `kernel.started` y
  `kernel.stopped`, sin suscriptores.
- **`AuditLog.record`** (`storage/audit.py`): escribe directamente en `audit_events`. Con conexión,
  entra en la transacción del cambio; sin conexión, se confirma aparte. Hay unas 40 llamadas. No
  tiene categoría ni empresa, y no valida el nombre del evento ni su payload.
- **Consecuencia:** un evento sin consumidor no se reintenta, y un fallo de auditoría revierte la
  operación completa.

### 1.4 Instalador

`SecurityService.bootstrap_administrator` crea la primera cuenta sin código de instalación. La
terminal lo llama cuando no hay cuentas, así que cualquiera que llegue primero se convierte en
administrador (hallazgo P-04).

## 2. Decisiones aplicadas

1. **Modelo multiempresa.** Tabla `companies`, con una empresa reservada `plataforma`. Cada cuenta
   tiene `company_id` obligatorio, fijado al crearla y no modificable (trigger). El actor de una
   operación se construye desde la sesión y la cuenta de la base de datos. Ninguna entrada de
   usuario puede cambiar la empresa. La plataforma puede actuar sobre cualquier empresa; una
   empresa solo sobre sí misma.
2. **Instalador.** Código de 128 bits, guardado como hash PBKDF2 y válido 30 minutos. Cinco
   intentos fallidos invalidan el código. Un solo uso. Al completarse, la fila de instalación pasa
   a `completed` y un trigger impide cualquier cambio o borrado posterior.
3. **Bus de eventos con auditoría.** Eventos tipados con catálogo (nombre, categoría y claves
   permitidas). Persistencia transaccional (outbox) en la misma transacción que el cambio. Entrega
   tras confirmar, consumidores idempotentes, reintentos, cola de fallidos y reenvío al arrancar.
   Categorías separadas: `operativo` y `seguridad`.

## 3. Migraciones

| Versión | Nombre | Cambios | Datos existentes | Reversión |
|---|---|---|---|---|
| 6 | `empresas` | Tabla `companies` con la fila `plataforma`. `accounts.company_id` con valor por defecto `plataforma`. Índice y triggers de integridad. | Las cuentas existentes pasan a la empresa `plataforma`. Era la única instalación, sin clientes; no se crea ninguna empresa ficticia. | Borra triggers e índice, elimina la columna y la tabla. |
| 7 | `instalacion` | Tabla singleton `installation`. `state = completed` si ya hay cuentas; `pending` si no. Triggers de bloqueo. | Una instalación existente con cuentas queda `completed`, así que el instalador no se reabre. | Borra triggers y tabla. |
| 8 | `eventos` | Tablas `event_outbox` y `event_deliveries`. En `audit_events`: `event_id` (único), `category`, `company_id` y `actor`. | Los eventos existentes conservan sus datos. `category` se rellena según el tipo. | Borra índices, elimina columnas y tablas. |

Reglas de la migración:

- Cada versión es transaccional. Un fallo deja la base como estaba.
- Antes de aplicar migraciones pendientes sobre una base existente se crea una copia en
  `storage/migraciones/` con la API de copia de SQLite, y se comprueba que se puede abrir.
- Si la base tiene migraciones desconocidas, se rechaza (sin cambios).
- Revertir la migración 7 y volver a aplicarla es seguro: la fila de instalación se recalcula a
  partir de las cuentas existentes.

## 4. Riesgos de la migración

- **Alteración de `accounts` y `audit_events`.** La copia previa y la transacción por versión lo
  mitigan. No hay reconstrucción de tablas con claves foráneas activas: la columna se añade con
  `ALTER TABLE`, sin borrar ni recrear `accounts`, porque eso activaría los borrados en cascada.
- **Reversión de la migración 6.** Elimina `company_id`. Solo debe hacerse con copia previa.
- **Copia previa con secretos.** La copia de `storage/migraciones/` contiene hashes de contraseñas
  y de sesiones. Tiene los mismos permisos que la base de datos. Hay que tratarla con el mismo
  cuidado que la base.
- **Auditoría consistente solo tras confirmar.** Un evento queda en el outbox dentro de la misma
  transacción que el cambio. La entrega en `audit_events` ocurre después, en el mismo proceso o
  al arrancar. Si el proceso cae entre ambas, el evento no se pierde.

## 5. Verificación realizada

**Pruebas.** 262 en total: las 214 existentes y 48 nuevas. Todas pasan.

Cuatro pruebas existentes cambiaron de procedimiento o de expectativa. Ninguna aserción de
seguridad se debilitó:

- `test_migrations_apply_once`: la lista de migraciones pasa a ser 1 a 8.
- `test_audit_log_records_and_lists`: usaba el nombre `prueba`, que el catálogo de eventos no
  admite. Ahora usa `version.activated`.
- `test_first_run_creates_the_administrator` y `test_bootstrap_refuses_mismatched_passwords`: la
  primera ejecución pide el código de instalación antes que los datos del administrador.

Nuevas pruebas por área:

| Área | Archivo | Casos |
|---|---|---|
| Instalador: código de un solo uso, hash, intentos, caducidad, bloqueo | `tests/test_installer.py` | 9 |
| Aislamiento entre empresas y permisos administrativos (API y terminal) | `tests/test_companies.py` | 16 |
| Bus de eventos: contrato, transacciones, idempotencia, reintentos, cola de fallidos, orden, reinicio | `tests/test_event_bus.py` | 14 |
| Migraciones: actualización desde v5 con datos, reversión, reaplicación, copia previa | `tests/test_migrations_stage2.py` | 8 |
| Terminal: código incorrecto en la instalación | `tests/test_terminal.py` | 1 |

**Calidad.** `ruff check` y `ruff format --check` sin avisos. `mypy --strict` sobre `src/` sin
errores.

**Pruebas de mutación.** Se introdujeron seis fallos a propósito en una copia de trabajo y se
comprobó que alguna prueba los detecta:

1. Comprobación de ámbito desactivada en `GrantStore`: detectada.
2. Comprobación de ámbito desactivada en `OperationGuard.run`: detectada.
3. Límite de intentos del código desplazado (`>` en lugar de `>=`): detectada.
4. Registro de entrega por consumidor eliminado: **no** la detectaba ninguna prueba. Con un solo
   consumidor, el estado `delivered` evita la repetición, así que la garantía solo importa cuando
   un consumidor falla y el otro ya tuvo éxito. Se añadió
   `test_a_retry_does_not_repeat_consumers_that_already_succeeded`, que ahora la detecta.
5. Opciones de plataforma visibles para cuentas de empresa: detectada.
6. Cuenta de empresa que elige la empresa de una cuenta nueva: detectada.

**Migraciones.** Tras actualizar desde v5, tras revertir a v5 y tras reaplicar, `PRAGMA
foreign_key_check` queda vacío e `integrity_check` devuelve `ok`.

- Actualizar desde v5 conserva cuentas, roles y eventos. Las cuentas pasan a `plataforma`, y los
  eventos existentes quedan sin empresa, visibles solo para la plataforma.
- Revertir a v5 conserva cuentas y eventos. Reaplicar restaura el esquema y la instalación se
  recalcula: con cuentas, queda `completed`.
- Una migración sin reversión bloquea la reversión antes de tocar nada.

**Copia previa.** Antes de migrar una base existente con migraciones pendientes, el núcleo copia
`natxajo.db` a `storage/migraciones/natxajo-previa-v<N>-<marca>.db`. No copia una base nueva ni una
base sin migraciones pendientes.

## 6. Limitaciones y pendientes

- **Kernel sin token.** La API interna del kernel sin token sigue siendo de confianza (P-01). La
  terminal y los servicios de usuario sí pasan por el guardián. El cierre completo es la etapa 8.
- **Empresas.** No se desactivan ni se renombran. No se borran mientras tengan cuentas. La
  plataforma no se puede borrar.
- **Roles.** Son un catálogo global de la plataforma. Una empresa no puede crear roles propios.
- **Código de instalación.** Se muestra en la misma terminal. Quien pueda ver esa terminal durante
  la instalación puede completarla. No hay un canal externo para entregarlo. El límite de intentos
  protege el código, no a quien lo ve.
- **Límite de intentos por código.** Los cinco intentos son por código. Cada ejecución de la
  terminal emite uno nuevo, así que el contador no frena a quien vuelva a ejecutarla. La protección
  contra la adivinación es la entropía del código, de 128 bits.
- **Copia previa.** Contiene hashes de contraseñas y de sesiones. Tiene los mismos permisos que la
  base de datos y no está cifrada.
- **Reversión de la migración 6.** Elimina `company_id` y la tabla de empresas. Revertir después de
  crear empresas pierde esa información. Solo debe hacerse con copia previa.
- **Auditoría.** La consistencia es eventual dentro del proceso. El evento se guarda en la misma
  transacción que el cambio y se entrega después de confirmarla. Si la entrega falla, el evento
  queda pendiente y se reintenta en la siguiente operación o al arrancar. Un evento pendiente
  retrasa a los posteriores hasta resolverse o pasar a fallido, para mantener el orden.
- **Consumidor persistentemente fallido.** Mientras un evento sigue pendiente, los posteriores no
  aparecen en `audit_events`. Es intencional. Tras cinco fallos el evento pasa a fallido.
- **Cola de fallidos.** Se consulta con `dead_events()` y se reencola con `requeue_dead()`, pero la
  terminal todavía no la muestra ni la reencola. Los eventos fallidos no generan auditoría
  adicional, porque el mismo mecanismo que falla es el que registraría el fallo.
- **Fallo tras confirmar.** Si la entrega falla por un error de base de datos después de confirmar
  el cambio, el error llega al llamador aunque el cambio esté confirmado. El evento sigue pendiente
  y se entrega después.
- **Revisión de plugins.** `record_review` escribe la revisión y la auditoría en transacciones
  separadas. Es un problema heredado de la fase 6 y queda pendiente.
- **Entorno.** Probado en Linux con Python 3.13. Windows y el lanzador `launcher.ps1` no se han
  probado en esta etapa.
