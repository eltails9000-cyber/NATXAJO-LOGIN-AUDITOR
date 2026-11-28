# Arquitectura

## Capas y reglas de dependencia

```
interfaces  ──►  kernel  ──►  security, configuration, storage, versioning, modules, plugins,
                             auditing, reporting, maintenance  ──►  core
```

- `core` no depende de nada del proyecto. Contiene excepciones y utilidades.
- `storage` y `configuration` no conocen el núcleo ni la terminal.
- `versioning` usa `storage` (base de datos y auditoría) y `core`.
- `security` usa `storage` y `core`. El actor de cada operación sale de la base de datos, nunca de la
  entrada del usuario.
- `kernel` compone los servicios en `kernel/composition.py`, el único módulo del núcleo que conoce
  los subsistemas concretos. Sus accesores leen los servicios con claves tipadas (`ServiceKey`) y
  no usan `cast`. Solo `composition.py` importa subsistemas en tiempo de ejecución; `kernel.py` los
  nombra únicamente en anotaciones de tipo.
- `modules` y `plugins` solo importan `core` y `storage`. Consumen contratos públicos de `core`.
- `interfaces` solo consume servicios del núcleo. No importa `security` ni `storage`. No contiene
  reglas de negocio.
- La interfaz gráfica vive en `interfaces/gui/`. Sus módulos importan solo `core`, `kernel` y
  otros módulos de `gui` por su ruta completa. Ningún módulo importa el paquete `gui` en sí:
  su `__init__` importa `server`, y esa importación crearía un ciclo.

## Reglas de dependencia

Verificadas por `tests/test_arquitectura.py` con análisis AST. Cada paquete solo puede importar los
paquetes de su fila, en tiempo de ejecución o en anotaciones de tipo. Cualquier otra importación
hace fallar la suite, y también los ciclos y la importación relativa.

| Paquete | Puede importar |
|---|---|
| `core` | ninguno |
| `storage` | `core` |
| `configuration` | `core`, `storage` |
| `versioning` | `core`, `storage` |
| `security` | `core`, `storage` |
| `modules` | `core`, `storage` |
| `plugins` | `core`, `storage` |
| `auditing` | `core`, `storage` |
| `reporting` | `auditing`, `core`, `storage` |
| `maintenance` | `core`, `storage` |
| `pruebas` | `core`, `storage` |
| `kernel` | `auditing`, `configuration`, `core`, `maintenance`, `modules`, `plugins`, `pruebas`, `reporting`, `security`, `storage`, `versioning` |
| `interfaces` | `core`, `kernel` |
| `(raiz)` | `core`, `kernel`, `interfaces` |

`(raiz)` son `main.py` y `__init__.py` del paquete raíz. Todo paquete puede importar el paquete
raíz, que solo contiene la versión.

Reglas adicionales, también verificadas:

- Solo `kernel/composition.py` importa subsistemas en tiempo de ejecución. `kernel.py` no usa `cast`.
- `modules/` y `plugins/` no usan `importlib`, `runpy`, `subprocess`, `eval`, `exec` ni funciones
  equivalentes. La lista de excepciones autorizadas está vacía.
- `hashlib` solo lo importan `core/utilities.py`, `core/ed25519.py` y `security/passwords.py`.
- No hay importaciones relativas ni ciclos entre módulos del paquete.

Las pruebas AST no verifican la forma de los datos que pasan entre paquetes, la ausencia de
duplicación de lógica (grafos, permisos) ni el comportamiento en tiempo de ejecución.

## Contratos compartidos

Los valores que varios subsistemas comparten se definen una sola vez:

- `core/contracts.py`: `PLATFORM_COMPANY` (`plataforma`), `SCOPE_DENIED`, `APPROVE_PERMISSION` y el
  protocolo `OperationGate`, que `plugins` usa en lugar del guardián concreto.
- `core/permissions.py`: formato de permisos, subsistemas y acciones del catálogo cerrado.
- `core/validation.py`: validadores de manifiestos y `kernel_matches`, la regla de compatibilidad
  de versión del núcleo.
- `core/exceptions.py`: la jerarquía de errores, incluida `SessionError`.

## Orden de arranque y parada

Arranque (`compose` en `kernel/composition.py`, llamado desde `Kernel.start`):

1. Carpetas de configuración y de datos.
2. Base de datos: se abre y se registra, para que un fallo posterior la cierre.
3. Si la base existía y tiene migraciones pendientes, copia consistente en `storage/migraciones/`.
4. Migraciones versionadas.
5. Outbox con el consumidor de auditoría, y auditoría.
6. Entrega de los eventos pendientes de una parada anterior.
7. Configuración, copias, módulos, versiones, seguridad y plugins. Seguridad va antes que plugins
   porque el gestor de plugins necesita el guardián de operaciones.
8. `kernel.started` en la auditoría. Solo después el núcleo pasa a `RUNNING`.

Parada (`Kernel.stop`):

1. `kernel.stopped` en la auditoría, antes de cerrar la base de datos.
2. Cierre de la base de datos y limpieza del contenedor de servicios.

Un fallo durante el arranque deja el núcleo en `FAILED`, cierra la base de datos si estaba abierta
y no construye nada después del fallo. Las pruebas de `tests/test_kernel_characterization.py`
protegen este orden.

## Ciclo de vida del núcleo

```
CREATED ──► STARTING ──► RUNNING ──► STOPPING ──► STOPPED
                 │                       ▲
                 └──► FAILED ────────────┘
```

Las transiciones no permitidas lanzan `LifecycleError`. Si el arranque falla, los servicios
ya abiertos se cierran y el núcleo queda en `FAILED`. Un núcleo parado no se puede reiniciar:
se crea otra instancia.

## Decisiones

**D1. Configuración JSON con esquema estricto.** Las claves desconocidas se rechazan para
detectar errores tipográficos. Las claves ausentes toman su valor por defecto. Cada cambio
guarda la versión anterior en `config/history/` y se escribe de forma atómica.

**D2. La exigencia de autorización para auditar no es configurable.** `auditing.require_authorization`
debe ser `true`. Es un límite de seguridad del documento maestro, no una preferencia.

**D3. Copias con manifiesto SHA-256.** Cada copia registra su hash. Una copia alterada o sin
manifiesto no se restaura. La restauración requiere `authorized=True` y no sobrescribe un
destino existente sin `overwrite=True`.

**D4. Migraciones versionadas.** Cada migración se aplica una vez, dentro de una transacción.
Si una migración falla, no deja cambios parciales. Una base de datos con migraciones que este
código no conoce se rechaza. Antes de migrar una base existente se guarda una copia en
`storage/migraciones/`.

**D5. Versiones como carpetas con manifiesto.** `versions/<versión>/manifest.json` describe
cada versión. El nombre de la carpeta debe coincidir con la versión declarada. El núcleo no
conoce ninguna versión concreta: solo sabe si una versión declara ser compatible con él.

**D6. Una sola versión activa.** La activa se guarda en `platform_metadata`. Cada activación
se registra en `audit_events` dentro de la misma transacción, así que nunca hay un cambio
sin registro. La reversión usa ese historial.

**D7. Compatibilidad por patrón.** `compatible_kernel` acepta una versión exacta (`0.1.0`) o
una familia de parches (`0.1.x`).

**D9. Módulos declarativos y tolerantes a fallos.** Un módulo es `modules/<id>/module.json` y
no ejecuta código. Si un manifiesto es inválido, solo ese módulo queda marcado en el diagnóstico;
el resto sigue funcionando. Habilitar un módulo habilita antes sus dependencias, y deshabilitar
uno se rechaza mientras otro módulo habilitado lo requiera. Así se mantiene el invariante de que
todo módulo habilitado tiene sus dependencias habilitadas. Los permisos se validan contra un
catálogo cerrado, pero aún no se aplican.

**D8. Sin estado global.** El contexto (`RuntimeContext`) recibe la ruta del proyecto. Así las
pruebas usan directorios temporales y no tocan el repositorio.

**D10. Multiempresa por cuenta.** Cada cuenta pertenece a una empresa (`company_id`), fijada al
crearla. Un disparador impide cambiarla. La empresa del actor se lee de la cuenta en la base de
datos. La plataforma (`plataforma`) actúa sobre todas las empresas; una empresa, solo sobre sí
misma. Las operaciones de infraestructura (versiones, módulos, plugins, copias) exigen la plataforma.

**D11. Instalación con código de un solo uso.** El primer administrador se crea con un código de
128 bits que se muestra una vez, se guarda como hash PBKDF2 y caduca a los 30 minutos. Cinco intentos
fallidos lo invalidan. Al completarse, la fila de instalación queda cerrada por un disparador.

**D12. Bus de eventos con outbox transaccional.** Los eventos tienen contrato: un catálogo cerrado
con claves obligatorias, opcionales y categoría. Se guardan en la misma transacción que el cambio y
se entregan después de confirmarla. Cada consumidor recibe cada evento una sola vez, gracias al
registro de entregas. Los fallos se reintentan y, tras cinco intentos, el evento pasa a cola de
fallidos. Al arrancar se entregan los pendientes. La auditoría es un consumidor más. Las categorías
`operativo` y `seguridad` se guardan por separado.

## Dónde vive cada cosa

| Dato | Ubicación | Notas |
|---|---|---|
| Configuración | `config/app.json` | Ignorado por git |
| Historial de configuración | `config/history/` | Ignorado por git |
| Copias de configuración | `config/backups/` | Ignorado por git |
| Base de datos | `storage/natxajo.db` | Ignorado por git |
| Copias de almacenamiento | `storage/backups/` | Ignorado por git |
| Manifiestos de versión | `versions/` | Versionado en git |
| Copias previas a migraciones | `storage/migraciones/` | Ignorado por git; contienen hashes |
| Configuración de pruebas | `config/pruebas/` | Ignorado por git. Formularios, cuentas sintéticas y límites; las contraseñas van en variables de entorno |
| Informes de pruebas | `reports/pruebas/` | Ignorado por git. Un archivo por exportación, con su SHA-256 registrado en la base de datos |
