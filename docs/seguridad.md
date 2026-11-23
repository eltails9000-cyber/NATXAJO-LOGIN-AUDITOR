# Seguridad y límites

## Uso previsto

La plataforma es una herramienta de auditoría defensiva. Solo debe usarse sobre sistemas propios
o con autorización verificable por escrito.

## Qué NO hace y no hará

Estos límites vienen del documento maestro y no se relajan:

- No implementa fuerza bruta, credential stuffing ni adivinación de contraseñas.
- No intenta acceder a cuentas de terceros.
- No evade controles de autenticación.
- No recolecta credenciales reales.
- No ejecuta pruebas contra objetivos sin autorización.

## Qué está implementado hoy

- **Restauraciones protegidas.** La configuración y el almacenamiento solo se restauran con
  `authorized=True`. Una copia alterada no se restaura. Un destino existente no se sobrescribe
  sin una confirmación adicional.
- **Auditoría.** Las activaciones de versión quedan registradas en `audit_events`, dentro de la
  misma transacción que el cambio.
- **Escritura atómica.** Los archivos de configuración y las copias se escriben en un temporal
  y luego se sustituyen. Un fallo a mitad de escritura no deja el archivo a medias.
- **Autorización de auditorías obligatoria.** El esquema de configuración no permite desactivarla.
- **Plugins firmados.** Un paquete se acepta solo si su firma Ed25519 corresponde a un editor
  registrado y no revocado, si cada archivo coincide con su hash y si su versión de API y de
  núcleo son compatibles. Un paquete alterado se rechaza, y la copia almacenada se vuelve a
  verificar antes de habilitarla. Un editor revocado deshabilita sus plugins y los que dependen de
  ellos. Los rechazos quedan en la auditoría. Límites: la verificación no es de tiempo constante,
  aceptable para datos públicos pero no para firmar secretos; la revisión del inventario de
  archivos es heurística y no sustituye la revisión humana.
- **Confianza protegida (P-05).** Dar de alta o revocar un editor de confianza, y registrar una
  revisión de terceros, exigen sesión válida, un permiso crítico del sistema
  (`plugins:nucleo:editor:administrar` o `plugins:nucleo:revision:administrar`), ámbito de
  plataforma, confirmación explícita y reautenticación reciente. Una cuenta de empresa no actúa
  sobre la confianza global, aunque tenga el rol de administrador. La escritura y su auditoría van
  en una transacción. La base impide cambiar la clave de un editor, reactivar un editor revocado y
  borrar editores (migración 9). Un paquete no puede declarar su propio nivel de confianza.
- **Cuentas y contraseñas.** Las contraseñas se guardan como PBKDF2-HMAC-SHA256 con sal aleatoria
  de 16 bytes y 600 000 iteraciones por defecto. Nunca se guardan en texto plano ni aparecen en la
  auditoría. La política exige entre 12 y 256 caracteres, al menos 4 caracteres distintos, y
  prohíbe usar el nombre de usuario como contraseña. Las comparaciones usan `hmac.compare_digest`.
- **Bloqueo por fallos.** Cinco fallos seguidos bloquean la cuenta durante 15 minutos. Mientras
  dura, cualquier intento, también con la contraseña correcta, recibe el mismo mensaje que una
  contraseña incorrecta y queda en la auditoría como `account.login_blocked`. Un usuario inexistente
  recibe ese mismo mensaje y realiza el mismo cálculo, así que la respuesta no revela qué cuentas
  existen. El contador y el bloqueo se leen y se escriben en una misma transacción: dos intentos
  simultáneos cuentan los dos, y un acierto no salta un bloqueo fijado durante su verificación.
- **Roles y separación de funciones.** Roles integrados `administrador`, `operador` y `auditor`.
  Ninguna cuenta puede tener a la vez `operador` y `auditor`. Un rol nuevo solo puede conceder
  permisos que posea quien lo crea, y la herencia admite como máximo 5 niveles.
- **Protección del último administrador.** No se puede deshabilitar ni quitar el rol de
  administrador al último administrador activo de la plataforma.
- **Sesiones.** La ficha de sesión tiene 256 bits aleatorios y la base de datos guarda solo su hash
  SHA-256. La ficha existe en memoria durante la sesión de terminal. Una sesión caduca tras 15
  minutos de inactividad o 8 horas desde su inicio. Cada cuenta puede tener hasta 3 sesiones
  activas; un inicio adicional se rechaza. Cerrar sesión, salir de la terminal o deshabilitar la
  cuenta invalida la sesión.
- **Reautenticación.** Las operaciones críticas exigen volver a escribir la contraseña en los 5
  minutos anteriores a la operación.
- **Permisos temporales.** Una cuenta solicita un permiso para 1 a 240 minutos. Lo aprueba otra
  cuenta que tenga `seguridad:nucleo:permiso:aprobar` y que también posea el permiso concedido.
  Nadie aprueba su propia solicitud. Al caducar, el permiso deja de aplicarse. Aprobar, rechazar o
  revocar es una transición condicionada: una solicitud no se resuelve dos veces, ni una rechazada
  pasa a activa.
- **Guardián de operaciones.** Toda acción de la plataforma pasa por el guardián: sesión válida,
  permiso requerido y, en las operaciones críticas (`CRITICAL_PERMISSIONS` en
  `security/guard.py`), confirmación explícita y reautenticación reciente. Las denegaciones y las
  ejecuciones quedan en la auditoría como `operation.denied` y `operation.executed`. Una operación
  sin empresa indicada es de plataforma: una cuenta de empresa no la ejecuta aunque tenga el permiso.
- **Menú filtrado.** La terminal solo muestra las opciones que la cuenta puede usar. Una opción
  no permitida se rechaza igualmente si se introduce a mano.
- **Empresas.** Cada cuenta pertenece a una empresa, fijada al crearla y protegida por disparadores.
  El guardián comprueba el ámbito antes de pedir confirmación: una cuenta de empresa no actúa sobre
  otra empresa, aunque tenga el permiso. Las solicitudes de permisos temporales se comprueban igual.
  La terminal filtra la auditoría y las solicitudes por empresa.
- **Instalador.** El primer administrador se crea con un código de 128 bits, que se muestra una vez,
  se guarda como hash PBKDF2, caduca a los 30 minutos y admite cinco intentos como máximo. Completada
  la instalación, un disparador impide reabrirla.
- **Bus de eventos y auditoría.** Solo se registran eventos del catálogo cerrado, con su categoría
  (`operativo` o `seguridad`) y sin claves con apariencia de secreto. Un evento se guarda en la misma
  transacción que el cambio y se entrega después. Los fallos se reintentan y no se pierden. Cada
  consumidor se ejecuta bajo un autorizador de SQLite: puede leer y escribir en tablas que no son de
  la plataforma; no puede tocar cuentas, sesiones, permisos, instalación ni el propio bus; la
  auditoría admite solo inserciones, y solo del consumidor de auditoría. Un consumidor que intente
  otra cosa falla y se reintenta hasta la cola de fallidos. Límite: la lista de tablas protegidas es
  manual, y el autorizador se ha comprobado en Linux, no en Windows.

## Controles de la etapa 4

- **Auditoría sin conexión.** El motor no envía solicitudes al sistema evaluado. Lee un documento
  declarado y, en la terminal, un archivo local. Registrar una evaluación exige una referencia de
  autorización escrita, pero la plataforma no la verifica.
- **Permisos nuevos.** `auditoria:nucleo:evaluacion:ejecutar` y `:leer`,
  `informes:nucleo:exportacion:escribir` y `:leer`, y `mantenimiento:nucleo:diagnostico:leer`. La
  limpieza, `mantenimiento:nucleo:limpieza:ejecutar`, es crítica. El diagnóstico y la limpieza son
  solo de plataforma: una cuenta de empresa, aunque sea administradora, no las ejecuta.
- **Aislamiento entre empresas.** Evaluaciones, informes y sus historiales son de una empresa. Una
  evaluación ajena responde igual que una inexistente.
- **Inmutabilidad.** Evaluaciones, hallazgos y exportaciones no se modifican ni se borran, por
  disparadores. Si alguien los quita y altera un hallazgo, la carga lo detecta.
- **Entrada.** Documentos con JSON estricto, límite de 256 KiB y claves desconocidas rechazadas sin
  repetirlas. Los archivos deben ser regulares: los enlaces simbólicos se rechazan.
- **Informes.** Las celdas CSV que podrían ejecutarse como fórmula se neutralizan. El HTML escapa
  todos los valores y no carga recursos externos. La empresa se valida antes de tocar el disco.
- **Limpieza.** Solo borra `*.tmp` regulares dentro de `config/`, `storage/` y `reports/`. Nunca sigue
  enlaces ni toca archivos fuera de esas carpetas. Exige confirmación y reautenticación reciente.
- **Reversión de migraciones.** Se comprueba la versión de SQLite antes de cambiar nada cuando la
  reversión necesita `DROP COLUMN`.
- **Límites.** No hay pruebas activas, verificación criptográfica de la autorización ni firma de
  informes.

## Qué NO está implementado

- **Auditoría activa.** No hay pruebas contra sistemas en ejecución (TLS, cabeceras HTTP, formularios).
  Requieren un registro de alcance y autorización que todavía no existe.
- **Actualización, rollback y cuarentena de plugins.** No existen. El rollback que sí hay es el de las
  versiones del núcleo.
- **Aislamiento de módulos.** No hay procesos separados, límites de recursos ni sandbox. Ningún
  módulo se ejecuta todavía, así que los permisos que un módulo declara no se aplican a ningún
  código. Los permisos de las operaciones de la plataforma sí se aplican. Cuando exista ejecución
  de módulos o plugins, la separación en carpetas o módulos no bastará: se documentará qué
  aislamiento real del sistema operativo se aplica.
- **Ejecución de plugins.** Habilitar un plugin solo registra su estado. No hay procesos separados
  ni límites de recursos. Cuando exista ejecución, se documentará el aislamiento real del sistema
  operativo que se aplica.
- **Multiempresa (parcial).** Las empresas no tienen aplicaciones ni entornos propios: comparten la
  base de datos, el almacenamiento y el conjunto de versiones de la plataforma. La API interna del
  kernel, sin token, no comprueba el ámbito; esa comprobación llega con la etapa 8. Los detalles
  están en `docs/AUDITORIA_ETAPA_2.md`, sección 5 (P-01): una API sin token puede crear
  administradores, cambiar contraseñas sin la anterior y activar versiones. La terminal no la usa sin
  el guardián. Dentro de un mismo proceso, ninguna API interna es una frontera de seguridad: la
  frontera real llegará con la ejecución de módulos o plugins en un proceso separado (etapa 8).
- **Confianza dentro del proceso (P-01).** Las escrituras internas de editores y de revisiones
  (`TrustStore._insert`, `TrustStore._revoke`, `ReviewLog.record`) no exigen token. Código que
  comparta el proceso y tenga una conexión puede usarlas. Las vías protegidas son
  `register_publisher`, `revoke_publisher` y `record_review`. Ver `docs/AUDITORIA_ETAPA_2.md`,
  sección 5.
- **Cifrado de datos sensibles.** La base de datos y las copias están en texto plano. Solo las
  contraseñas se guardan como hash; cuentas, roles, sesiones y auditoría no están cifrados.
- **Integridad de la auditoría.** Los eventos no están encadenados ni firmados. Quien pueda escribir
  en la base de datos puede alterarlos sin que se detecte.
- **Primer administrador.** El código de instalación se muestra en la misma terminal. Quien pueda
  ver esa terminal durante la instalación puede completarla. No hay un canal externo para entregar el
  código. El límite de cinco intentos es por código: cada ejecución emite uno nuevo. La protección
  contra la adivinación es la entropía del código (128 bits).
- **Gestión de cuentas desde la terminal.** La terminal permite crear cuentas en la empresa de la
  sesión, crear y listar empresas (solo la plataforma), y solicitar, aprobar o rechazar permisos
  temporales dentro del ámbito de la empresa. Revocar permisos, deshabilitar cuentas, cambiar roles
  y cambiar contraseñas solo están en la API (`kernel.security`).
- **Recuperación de acceso.** No hay recuperación de contraseñas ni borrado de cuentas. Una cuenta
  solo se deshabilita.
- **Desbloqueo.** No hay desbloqueo manual. Una cuenta bloqueada vuelve a estar disponible cuando
  caduca el bloqueo. El bloqueo es por cuenta: cualquiera con acceso a la terminal puede bloquear
  una cuenta conocida provocando cinco fallos.
- **Coste de inicio.** Cada comprobación de contraseña tarda unos 0,1 s con los parámetros por
  defecto en el entorno de desarrollo. Las pruebas usan 1 000 iteraciones; ese valor no debe usarse
  en producción.

## Permisos de archivos

Los datos de ejecución (`config/`, `storage/`) se crean con los permisos por defecto del sistema
operativo. En Windows conviene restringir el acceso a la carpeta del proyecto a la cuenta que
ejecuta la plataforma.
