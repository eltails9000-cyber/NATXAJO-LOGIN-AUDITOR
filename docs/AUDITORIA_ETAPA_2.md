# Auditoría independiente posterior a la etapa 2

Commit auditado: `9a371c7` en la rama `etapa-2-multiempresa-instalador-bus`. Esta auditoría
corrige defectos reales con pruebas de regresión. No reconstruye la etapa 2 ni cambia funciones
verificadas sin una razón técnica concreta.

## 1. Niveles de verificación

Cada conclusión indica el nivel en que está comprobada. Ninguna se declara segura solo porque sus
pruebas pasan.

- **Verificación estática:** lectura del código y búsquedas sistemáticas. Demuestra que el código
  dice lo que se afirma; no demuestra su comportamiento en ejecución.
- **Pruebas automatizadas:** pytest, Ruff y mypy en el entorno de desarrollo (Linux, Python 3.13,
  SQLite 3.53.1). Demuestran comportamiento en ese entorno.
- **Pruebas reales en Windows:** no realizadas. No hay entorno Windows disponible. Ninguna
  afirmación de compatibilidad con Windows se basa en ejecución. El procedimiento para hacerlo está
  en `docs/PRUEBAS_WINDOWS.md`.

## 2. Resumen

- Se confirmaron **siete defectos** de comportamiento. Cada uno se reprodujo con una prueba que
  falla en el código del commit auditado (14 pruebas en rojo) y se corrigió con un cambio acotado.
- Quedan abiertos un riesgo de diseño (P-01: API interna del núcleo sin token) y varios riesgos
  menores, documentados en las secciones 4 y 8.
- Cifras: línea base 262 pruebas aprobadas. Después de la auditoría, **279 aprobadas**: las 262
  originales sin cambios en sus aserciones, más 17 nuevas en
  `tests/test_auditoria_postimplementacion.py`. Ruff, el formato y mypy en modo estricto no dan
  errores.

## 3. Hallazgos por severidad

Las pruebas de regresión están en `tests/test_auditoria_postimplementacion.py`. «Roja antes»
indica que la prueba falló con el código del commit `9a371c7`.

| ID | Severidad | Estado | Dónde | Comportamiento | Evidencia |
|---|---|---|---|---|---|
| A-01 | Alta | Corregido | `security/guard.py`, `OperationGuard.run` | Sin `company_id`, el guardián no comprobaba el ámbito. Una cuenta de empresa con rol `administrador` ejecutaba una operación de plataforma (versiones, copias, empresas...). La terminal no es explotable, porque pasa siempre la empresa de plataforma; la API del núcleo sí. | Verificación estática y roja: `DID NOT RAISE AuthorizationError`. Prueba `test_an_operation_without_company_is_platform_only`. |
| A-02 | Alta | Corregido | `security/accounts.py`, `check_password` | El contador de fallos se leía fuera de la escritura. Dos intentos solapados perdían un incremento: el contador quedaba en 1 en lugar de 2, y el bloqueo llegaba más tarde. | Roja: `assert 1 == 2`. Prueba `test_concurrent_failed_attempts_are_all_counted`. |
| A-03 | Alta | Corregido | `security/accounts.py`, `check_password` | El bloqueo se comprobaba solo al principio del intento. Si otro intento lo fijaba durante la verificación, un acierto con la contraseña correcta lo saltaba y además reseteaba el contador. El spec exige que el bloqueo rechace también la contraseña correcta. | Roja: `DID NOT RAISE`. Prueba `test_a_lock_set_while_the_correct_password_is_checked_still_applies`. |
| A-04 | Alta | Corregido | `security/grants.py`, `approve`, `reject`, `revoke` | La comprobación de estado era previa a un `UPDATE` sin condición. Una solicitud rechazada podía pasar a activa si otra operación la aprobaba en esa ventana. También podía aprobarse dos veces, con dos eventos de auditoría. | Roja: `DID NOT RAISE ValidationError`. Prueba `test_a_grant_is_decided_only_once`. |
| A-05 | Media | Corregido | `security/sessions.py`, `open` | El límite de tres sesiones simultáneas se comprobaba fuera de la transacción. Dos inicios simultáneos podían crear una cuarta sesión. | Roja: `DID NOT RAISE AuthorizationError`. Prueba `test_the_session_limit_is_checked_inside_the_write_transaction`. |
| A-06 | Media | Corregido | `storage/outbox.py`, `_deliver` | La comprobación de «ya entregado» estaba fuera de la transacción del consumidor. Otro despachador que confirmara la entrega en medio podía hacer que el consumidor se ejecutara dos veces. Hoy el único consumidor (auditoría) es idempotente, pero un consumidor futuro no tendría esa garantía. | Roja: `assert 1 == 0` sobre las llamadas al consumidor. Prueba `test_a_delivery_committed_by_another_dispatcher_is_not_repeated`. |
| A-07 | Media-alta | Corregido | `storage/outbox.py`, `_run_consumer` y `_consumer_policy`; `storage/audit.py`, `AuditConsumer.writes_audit` | Un consumidor recibía una conexión sin restricciones. Podía reescribir o borrar la auditoría y la cola de eventos, alterar cuentas, sesiones, instalación o permisos, o crear tablas y ejecutar PRAGMA. | Roja en las 8 sentencias de prueba. Ahora cada una devuelve `not authorized`. Pruebas `test_a_consumer_cannot_alter_the_platform_or_its_history` (8 casos) y `test_the_restriction_ends_with_the_consumer_run`. |
| P-01 | Alta (diseño) | Abierto y documentado | `security/service.py`, almacenes y gestores de versiones, módulos, plugins, copias y configuración | La API del núcleo, sin token, puede crear cuentas con cualquier rol, cambiar contraseñas sin la anterior, cambiar roles, deshabilitar cuentas, activar versiones, habilitar plugins y restaurar copias. Ver la sección 5. | Estática. La terminal solo las usa con el guardián (`run` o `check_scope`). |
| A-08 | Baja | Documentado | `security/installer.py`, `issue_code` | Cada emisión reinicia `code_failed_attempts`. El límite de cinco intentos es por código, no por instalación. Con 128 bits de entropía no es explotable en la práctica. Quien pueda llamar a `issue_code` antes de la instalación puede emitir códigos sin límite. Ya constaba en `docs/seguridad.md`. | Estática. |
| A-09 | Baja | Documentado | `storage/outbox.py`, `_dispatch` | No hay espera entre reintentos. Cada `emit` confirmado dispara una pasada de entrega, así que los cinco intentos pueden agotarse en pocas operaciones seguidas ante un fallo transitorio. Corregirlo exige una columna de próximo intento, es decir, un cambio de esquema. | Estática y lectura del flujo de `emit` → `_dispatch`. |
| A-10 | Baja | Documentado | `launcher.ps1` y `README.md` | Con la política de ejecución por defecto de los equipos cliente de Windows (`Restricted`), `.\launcher.ps1` no se ejecuta. El README no lo indicaba. Se añade el comando con `-ExecutionPolicy Bypass`. | Estática. Comportamiento de Windows no comprobado en este entorno. |
| A-11 | Baja | Abierto | `storage/migrations.py`, reversión de las migraciones 6 y 8 | `ALTER TABLE ... DROP COLUMN` requiere SQLite 3.35 o posterior. No hay comprobación en tiempo de ejecución. En una versión anterior la reversión falla dentro de su transacción, sin cambios parciales, pero no avisa antes. | Estática. |
| A-12 | Baja | Documentado | `plugins/store.py`, `copy_in` y `remove` | `shutil.rmtree(..., ignore_errors=True)` puede dejar restos si un archivo está bloqueado (en Windows es habitual). El efecto es un fallo cerrado: `copy_in` rechaza una copia existente, y `enable` vuelve a verificar la copia almacenada y su integridad frente al registro antes de habilitarla (`plugins/manager.py`, líneas 327 y 332). | Estática. No comprobado en Windows. |
| A-13 | Info | Pendiente | `main.py` | Ctrl+C produce un rastreo de error. `kernel.stop()` se ejecuta en `finally`, y `Database.transaction` revierte ante cualquier excepción, así que no se pierden datos confirmados. | Estática. |
| A-14 | Info | Documentado | `main.py`, `interfaces/terminal/app.py` | Si la salida se redirige a un archivo en Windows, los caracteres fuera de la página de códigos del sistema pueden provocar un error de codificación. | Estática. No comprobado en Windows. |
| A-15 | Info | Documentado | `security/accounts.py`, `check_password` | «Cuenta deshabilitada» se devuelve solo tras una contraseña correcta. Revela el estado de la cuenta solo a quien ya conoce la contraseña. | Estática. |

## 4. Revisión por áreas

### 4.1 Aislamiento entre empresas (objetivo 1)

**Datos con ámbito de empresa, por tabla o relación:**

| Dato | Cómo se acota | Comprobación |
|---|---|---|
| `accounts.company_id` | Fijado al crear. Disparadores de inmutabilidad y de existencia de la empresa. | Estática y pruebas existentes. |
| `audit_events.company_id` | Terminal: filtra por empresa salvo para la plataforma. `list_events(company_id=...)` filtra. | Estática y pruebas existentes. Los eventos sin empresa solo los ve la plataforma. |
| `permission_grants` | Por la cuenta solicitante (`username` → `accounts.company_id`). `list_grants(company_id)`, y `_require_scope` en solicitar, aprobar, rechazar y revocar. | Estática y pruebas existentes. |
| `sessions` | Por `username`. La empresa se lee de la cuenta en cada operación, nunca de la entrada. | Estática. |
| `event_outbox.company_id` | Columna de la empresa del evento. El despacho interno no filtra, porque es infraestructura. | Estática. |
| `companies` | Solo la plataforma crea empresas (la terminal exige `SCOPE_PLATFORM`). Una empresa con cuentas no se puede borrar, y la plataforma no se puede borrar. | Estática y pruebas existentes. |
| `roles`, `role_grants`, `role_parents` | Catálogo global de la plataforma. Sin empresa por diseño. | Estática. |
| `platform_metadata`, `module_states`, `plugin_*`, copias y configuración | Infraestructura: exigen la empresa de plataforma (D10). | Estática. La terminal lo exige (`SCOPE_PLATFORM`). La API no (P-01). |

**Exportaciones, informes y tareas programadas:** no existen en el código del commit. La opción
«Diagnósticos, informes y mantenimiento» es un marcador de la fase 11. Cuando existan, cada
informe deberá recibir el ámbito de empresa. Es un requisito pendiente, no un hallazgo.

**Rutas que pueden omitir el ámbito:**

1. A-01: `OperationGuard.run` sin `company_id`. Corregido.
2. P-01: métodos de los servicios sin guardián (sección 5).
3. `audit.list_events(company_id=None)` y `grants.list_grants(company_id=None)` devuelven todas las
   empresas. Es correcto para la plataforma, pero la API no lo impide para otros llamadores.

**Cambio del propio ámbito por un usuario:** no hay ruta en la terminal ni en la API que cambie
`accounts.company_id`. Un disparador lo impide a nivel de base de datos. La terminal fuerza la
empresa de la sesión al crear cuentas. Una cuenta de empresa no crea empresas, no solicita ni
resuelve permisos fuera de su empresa, y ante una cuenta ajena recibe el mismo mensaje que ante una
cuenta inexistente (`_request_grant` en la terminal).

**Permisos globales y administrativos:** el rol `administrador` tiene `*:*:*:*`, incluido el de
administrar empresas. Un administrador de empresa tiene ese permiso, pero el ámbito lo deniega en
las operaciones de plataforma. Las pruebas existentes lo cubren desde la terminal, y A-01 lo cierra
para la API.

### 4.2 Instalador (objetivo 2)

| Control | Estado | Evidencia |
|---|---|---|
| Entropía del código | 128 bits con `secrets.token_urlsafe(16)`. | Estática. |
| Hash | PBKDF2-HMAC-SHA256 con sal. La comparación usa `hmac.compare_digest`. | Estática (`security/passwords.py`, línea 59). |
| Caducidad | 30 minutos, comparados con el reloj inyectado dentro de la transacción. | Estática y prueba existente de código caducado. |
| Un solo uso | Estado, `code_hash` y caducidad se actualizan en la misma transacción. Un disparador impide reabrir. | Estática, pruebas existentes y `test_the_installation_code_is_single_use_across_connections` (nueva: una segunda conexión a la misma base encuentra la instalación cerrada). |
| Concurrencia | `complete` y `issue_code` escriben con `BEGIN IMMEDIATE`, que serializa a los procesos. | Estática (`storage/database.py`). Una carrera real con dos procesos **no está probada**. |
| Reapertura | `installation` no admite UPDATE ni DELETE tras completarse (disparadores). Un consumidor no puede tocarla (A-07). | Estática, pruebas existentes y autorizador. |
| Secretos en registros, excepciones e informes | El código aparece solo en la salida de la terminal durante la instalación. La auditoría `installation.code_issued` no lleva datos. Las excepciones no incluyen el código. | Estática. La copia previa a migraciones contiene `code_hash` (un hash, no el código). Documentado. |

### 4.3 Bus de eventos (objetivo 3)

| Control | Estado | Evidencia |
|---|---|---|
| Atomicidad outbox y negocio | `emit(connection=...)` escribe en la misma transacción. Un rollback descarta el evento. | Prueba existente. |
| Idempotencia por consumidor | Clave primaria `(event_id, consumer)` y comprobación dentro de la transacción (A-06). | Roja y verde, sección 3. |
| Fallos parciales | La transacción del consumidor se revierte entera, sin escritura parcial. | Prueba existente. |
| Reintentos y cola de fallidos | Cinco intentos, después `dead`. `requeue_dead` reencola. Sin espera entre intentos (A-09). | Pruebas existentes. |
| Reinicios | Al arrancar se entregan los eventos pendientes. | Prueba existente. |
| Orden | Entrega en orden de `seq`. Un evento pendiente bloquea a los posteriores, por diseño. | Prueba existente. |
| Permisos del consumidor | Autorizador de SQLite durante la ejecución (A-07). La restricción termina al acabar el consumidor. | Pruebas nuevas. |
| Separación operativo y seguridad | Cada evento del catálogo tiene categoría. El catálogo tiene 34 entradas: 9 operativas y 25 de seguridad. | Estática y prueba existente. |

**Limitaciones del autorizador:** impide las escrituras prohibidas en tablas de la plataforma. La
lista de tablas protegidas (`PROTECTED_TABLES`) se escribió a mano; una tabla nueva de la plataforma
debe añadirse ahí. Un consumidor de auditoría puede insertar eventos, pero no editarlos ni
borrarlos. El autorizador es una función de SQLite: se comprobó en este entorno, no en Windows.

### 4.4 Permisos temporales, bloqueo y sesiones

Los cambios de A-02, A-03, A-04 y A-05 se describen en la sección 3. El flujo es el mismo y las
pruebas existentes siguen pasando sin cambios en sus aserciones. El bloqueo sigue siendo por cuenta:
cualquiera con acceso a la terminal puede bloquear una cuenta conocida, como ya constaba.

## 5. P-01: API interna del núcleo sin token

**Qué es.** `Kernel` expone sus servicios como atributos públicos (`kernel.security`,
`kernel.versions`, `kernel.modules`, `kernel.plugins`, `kernel.audit`...). Sus métodos no exigen
ninguna sesión. Un código que tenga la instancia puede actuar como la plataforma.

**Quién puede llamarla hoy.**

- La terminal llama a esos métodos solo dentro de `OperationGuard.run` o `check_scope`. Se
  comprobó en `_dispatch`: todas las opciones con permiso pasan por el guardián, y las tres sin
  permiso (9, 15 y 17) no modifican infraestructura.
- Las pruebas la usan directamente.
- No existen módulos ni plugins que se ejecuten. `docs/seguridad.md` lo declara. Por eso el riesgo
  es latente, no explotable desde la aplicación actual.

**Privilegios que concede sin token.**

| Superficie | Métodos relevantes | Lo que permite |
|---|---|---|
| `security` | `create_account` (cualquier rol y empresa), `disable_account`, `login`, `logout`, `reauthenticate` | Crear administradores. |
| `security.accounts` | `change_password`, `set_roles`, `set_status`, `check_password` | Cambiar cualquier contraseña sin la anterior, y cambiar roles y estado. |
| `security.grants` | `request`, `approve`, `reject`, `revoke` | Conceder permisos, con el `can` que se le pase. |
| `security.sessions` | `open`, `close`, `close_all`, `validate` | Abrir sesiones de cualquier cuenta. |
| `security.companies` | `create` | Crear empresas. |
| `security.installer` | `issue_code`, `complete` | Emitir código y completar la instalación mientras esté pendiente. |
| `versions` | `load`, `rollback` | Activar otra versión de la plataforma. |
| `modules` | `enable`, `disable` | Cambiar módulos habilitados. |
| `plugins` | `install_package`, `install_from_repository`, `enable`, `disable`, `uninstall`, `record_review`, `revoke_publisher` | Instalar y habilitar plugins, y revocar editores. |
| `storage/backups` | `restore` | Restaurar copias. |
| `configuration` | `set`, `restore` | Cambiar la configuración. |
| `audit` | `list_events(company_id=None)` | Leer la auditoría de todas las empresas. |

**Análisis.** Dentro de un mismo proceso de Python no hay frontera de seguridad: cualquier código
con la instancia puede llamar a cualquier método, aunque lo llame «interno». Por eso el nombre no
basta, y tampoco basta una comprobación de tipo. Un guardián que no se pueda eludir solo existe si
el código no comparte proceso con el que hay que proteger.

**Propuesta, por etapas:**

1. **Ahora (sin cambiar el comportamiento):** dejar los almacenes como atributos privados
   (`_accounts`, `_grants`...). Dejar a `kernel.security` como única fachada pública, y documentar
   la lista de la tabla como «API de confianza del propio proceso».
2. **Etapa 8, antes de ejecutar cualquier módulo o plugin:** código de módulos y plugins en un
   proceso separado. El núcleo expone una fachada remota en la que cada llamada lleva el token de
   sesión y pasa por `OperationGuard`. Al proceso del módulo no se le envía ninguna instancia de
   `Kernel`. Solo así la frontera es real.
3. **Como mejora previa a la etapa 8:** los métodos que mutan estado reciben un llamador (`Actor`)
   que solo produce `OperationGuard.actor_for(token)`. Un llamador de sistema existe únicamente
   dentro del arranque (instalador). Esto evita usos accidentales, pero no es una frontera dentro
   del proceso.

**Decisión de esta auditoría:** no se implementa ahora. Cambiaría la API pública de la etapa 2 en
todas las pruebas y en la terminal, y el objetivo era no cambiar funciones verificadas sin una
justificación concreta. Riesgo aceptado hasta la etapa 8, y condición para ejecutar módulos o
plugins.

## 6. Windows 10 y 11 (objetivo 5)

Todo lo de esta sección es **verificación estática**. Ninguna afirmación se ha comprobado en
Windows.

| Área | Hallazgo estático | Riesgo |
|---|---|---|
| Rutas | `pathlib` en todo el código. No hay separadores literales de Windows. | Bajo. Sin probar con rutas con espacios ni caracteres no ASCII. |
| Codificación | Toda la E/S de texto indica `encoding="utf-8"`. La E/S binaria está en `core/utilities.py`. | Bajo. Ver A-14 para la salida redirigida. |
| Escritura atómica | `mkstemp`, `fsync`, `os.replace` y limpieza del temporal. En Windows `os.replace` falla si el destino está abierto por otro proceso, y entonces el destino no cambia. | Bajo, fallo cerrado. |
| Bloqueo de archivos | La base se abre con una conexión. Las copias usan la API de copia de SQLite, no `shutil.copy` sobre la base abierta. Las fixtures cierran las conexiones. | Medio sin probar: un antivirus o un editor puede bloquear archivos. |
| Permisos | No hay `os.chmod`: no se fijan permisos explícitos. La base, las copias y la configuración quedan con los predeterminados del sistema de archivos (en Windows, la ACL heredada del directorio). Documentado en `docs/seguridad.md`. Comportamiento no comprobado. | Medio: conviene restringir la carpeta del proyecto. |
| Procesos y señales | No se usan señales, `subprocess` ni `fcntl`. Ctrl+C produce `KeyboardInterrupt` (A-13). | Bajo. |
| SQLite | Versión mínima 3.35 para revertir migraciones (A-11). Python para Windows incluye su propia versión de SQLite, no comprobada. | Bajo-medio. |
| Dependencias | Sin dependencias de ejecución (`dependencies = []`). Desarrollo: pytest, ruff, mypy. | Bajo. |
| Lanzador | `launcher.ps1` depende de la política de ejecución (A-10). Su búsqueda de Python (`py -3.11`, `py -3`, `python`) es lógica estática. | Medio: no ejecutado. |
| Copia de plugins | `rmtree` con `ignore_errors` (A-12). Fallo cerrado. | Bajo-medio. |

**Conclusión sobre Windows:** no se puede afirmar compatibilidad verificada. El código no usa
llamadas específicas de POSIX, y las dependencias son mínimas. Pero las pruebas automatizadas
corren solo en Linux, y el lanzador nunca se ha ejecutado. Para verificarlo, sigue
`docs/PRUEBAS_WINDOWS.md` en Windows 10 y 11 con Python 3.11 y 3.13.

## 7. Calidad y repositorio (objetivo 6)

| Comprobación | Línea base (`9a371c7`) | Después de la auditoría |
|---|---|---|
| `python -m pytest` | 262 aprobadas | 279 aprobadas (262 originales sin cambios + 17 nuevas) |
| `ruff check .` | Sin errores | Sin errores |
| `ruff format --check .` | Sin cambios pendientes | Sin cambios pendientes |
| `mypy --strict src` | Sin errores (60 archivos) | Sin errores (60 archivos) |

Las pruebas de regresión: 14 fallaban antes de corregir, 3 son de comportamiento normal y
protegen contra un exceso de restricción o contra una regresión (`test_a_company_operation...`,
`test_the_restriction_ends...` y `test_the_installation_code...`). Esta última se añadió después de
las correcciones y pasa desde el primer momento; por eso se marca como guarda, no como prueba roja.

**Repositorio:** `git ls-files` no contiene bases de datos, copias, configuraciones de ejecución,
claves ni archivos personales. Las rutas que coinciden con patrones sensibles son código fuente
bajo `src/natxajo_auditor/storage/`. `.gitignore` excluye `/config/`, `/storage/`, `.env` y
`.streamlit/secrets.toml`.

## 8. Riesgos residuales

1. **P-01** (sección 5). Abierto hasta la etapa 8. Es condición para ejecutar módulos o plugins.
2. **Windows no verificado** (sección 6). Pendiente de `docs/PRUEBAS_WINDOWS.md`.
3. **Consumidores en el mismo proceso.** El autorizador limita a los consumidores, pero es código
   Python en el proceso. Un consumidor malicioso puede eludir el mecanismo con el propio código del
   proceso (P-01).
4. **Auditoría sin integridad criptográfica.** Quien escriba en la base puede alterar la auditoría
   (`docs/seguridad.md`). Las restricciones de los consumidores no cambian eso.
5. **Límite de reintentos sin espera** (A-09) y **reversión sin comprobar SQLite** (A-11).
6. **Instalación:** el código se muestra en la misma terminal y se puede emitir de nuevo sin
   límite mientras la instalación esté pendiente (A-08).
7. **Carreras reales entre procesos** no están probadas. Las pruebas usan conexiones y transacciones
   deterministas.

## 9. Recomendación sobre la Pull Request

**Lista para abrir la PR como revisión de la etapa 2**, con estas condiciones:

1. La PR incluye esta auditoría y sus correcciones (`tests/test_auditoria_postimplementacion.py`).
2. La descripción indica que Windows no está verificado y que las pruebas se ejecutaron solo en
   Linux.
3. P-01 queda como riesgo aceptado hasta la etapa 8.

**No recomiendo fusionar en `main` como «verificada en Windows»** hasta ejecutar
`docs/PRUEBAS_WINDOWS.md` en Windows 10 y 11 con Python 3.11 y 3.13, y registrar el resultado.
