# Motor de pruebas HTTP y formularios (etapa 5)

Este documento describe lo que el motor hace hoy, cómo configurarlo y qué queda fuera. Es un
instrumento de **auditoría defensiva**: comprueba cómo responde un servidor de prueba autorizado
ante formularios de autenticación con cuentas sintéticas. No sirve para atacar sistemas ni para
probar contraseñas reales.

## Alcance

El motor solo opera contra **objetivos registrados** (orígenes `http://` o `https://` que un
administrador ha dado de alta con confirmación). Cualquier otro origen se rechaza antes de abrir
una conexión.

Lo que hace:

- Envía peticiones POST de formularios (y GET de la página para leer un token CSRF) a un objetivo
  registrado, con las cuentas sintéticas configuradas.
- Clasifica cada respuesta (aceptada, rechazada, bloqueada, error o inconsistente) y la compara con
  lo esperado.
- Mide el tiempo de cada petición y registra el código HTTP.
- Guarda cada ejecución y sus resultados en la base de datos, y exporta informes verificables.

Lo que **no** hace (ver la última sección): no sigue redirecciones, no prueba TLS ni cabeceras, no
genera contraseñas candidatas, no hace fuerza bruta ni credential stuffing, y no lee contraseñas
desde ficheros de configuración.

## Arranque

Desde la carpeta del proyecto, con Python 3.11 o superior:

```text
python main.py forms list --usuario admin
natxajo.cmd forms list --usuario admin         (CMD, en la carpeta del proyecto)
.\natxajo.ps1 forms list --usuario admin       (PowerShell 5.1 o 7)
```

`natxajo` también está registrado como comando si el paquete se instala (`pip install .`). La
contraseña se pide sin eco. Para automatizar, `--contrasena-desde-entrada` la lee de la entrada
estándar (una línea). No se acepta la contraseña como argumento ni como variable de entorno, para que
no quede en el historial de la consola.

## Configuración

Los archivos viven en `config/pruebas/` (carpeta ignorada por git). Todos son JSON con
`"version": 1`. Ningún archivo es obligatorio: sin ellos no hay formularios ni cuentas, y los
límites toman sus valores por defecto.

### Formularios (`formularios.json`)

```json
{
  "version": 1,
  "formularios": [
    {
      "id": "login",
      "tipo": "usuario_contrasena",
      "ruta": "/login",
      "campos": {"identidad": "usuario", "contrasena": "clave"},
      "longitudes": {"identidad": [2, 32], "contrasena": [1, 64]},
      "extra": {},
      "csrf": {"campo": "csrf_token", "pagina": "/login"},
      "respuesta": {
        "exito": ["Bienvenido"],
        "fallo": ["Credenciales incorrectas", "es obligatorio", "no es válido"],
        "bloqueo": ["Demasiados intentos"],
        "ruta_login": "/login"
      }
    }
  ]
}
```

- `tipo`: `usuario_contrasena`, `correo_contrasena`, `nombre_usuario_contrasena`,
  `identificador_contrasena` o `usuario_contrasena_mfa`. El tipo `usuario_contrasena_mfa` exige el
  bloque `mfa`.
- `campos`: nombre real de los campos de identidad y contraseña en la aplicación. Son configurables
  para adaptarse a cada aplicación de prueba.
- `longitudes`: mínimo y máximo de cada campo. Las matrices de longitud usan estos valores.
- `extra`: campos fijos que se envían en cada petición (texto corto).
- `csrf`: nombre del campo oculto y página donde aparece el token. El motor lo lee antes de cada
  envío.
- `mfa`: campo del código, ruta del segundo factor y marcador de la página de desafío.
- `respuesta`: marcadores de texto. `exito` y `fallo` se buscan en el cuerpo; `bloqueo` indica un
  control del servidor; `ruta_login` es la ruta del formulario (una redirección a ella es un rechazo).

### Cuentas sintéticas (`cuentas.json`)

```json
{
  "version": 1,
  "cuentas": [
    {
      "id": "a",
      "usuario": "prueba-a",
      "variable_contrasena": "NATXAJO_PRUEBA_CONTRASENA_A",
      "variable_mfa": "NATXAJO_PRUEBA_MFA_A",
      "correo": "prueba-a@example.com"
    }
  ]
}
```

- El usuario debe empezar por `prueba-` o `sintetica-`, y el correo debe ser de un dominio de
  prueba (`example.com`, `example.org`, `example.net`, `*.invalid` o `*.test`).
- La contraseña **no está en el archivo**. Se lee del entorno en cada ejecución, con el nombre de
  la variable declarado (`NATXAJO_PRUEBA_…`). Si falta, la ejecución se rechaza antes de enviar nada
  y el mensaje nombra la variable, nunca su valor.
- `variable_mfa` es el código de prueba del segundo factor. Solo lo usan las pruebas MFA.
- Un usuario igual a una cuenta de la plataforma se rechaza: las cuentas reales no se usan.

### Límites (`limites.json`)

| Clave | Por defecto | Mínimo | Máximo | Qué controla |
|---|---|---|---|---|
| `max_solicitudes` | 100 | 1 | 500 | Peticiones por ejecución (incluye las GET de token) |
| `max_cuentas` | 10 | 1 | 50 | Cuentas sintéticas por ejecución |
| `concurrencia` | 1 | 1 | 4 | Peticiones simultáneas |
| `pausa_ms` | 0 | 0 | 5000 | Pausa antes de cada envío |
| `timeout_s` | 5 | 0.5 | 30 | Tiempo máximo por petición |
| `max_intentos` | 6 | 1 | 10 | Intentos del procedimiento de límite de frecuencia |

Un valor fuera de rango es un error de configuración que nombra el campo.

### Objetivos y cuentas por línea de comandos

```text
natxajo targets add http://127.0.0.1:8080 --confirmar
natxajo targets list
natxajo accounts list
```

## Comandos

Todos piden usuario y contraseña. Los comandos marcados con **(crítico)** ejecutan pruebas activas
o cambian la lista de objetivos: exigen `--confirmar` y reautenticación con la misma contraseña.

| Comando | Qué hace | Crítico |
|---|---|---|
| `forms list` | Formularios configurados | |
| `forms inspect <id>` | Campos, longitudes, CSRF, MFA y reglas | |
| `forms validate <id>` | Cuentas, variables de entorno, código MFA y declaración del token CSRF (sin red) | |
| `forms test --suite validation\|format\|login-validation` | Suite de formulario | sí |
| `auth test --suite credentials\|synthetic-accounts` | Credenciales y cuentas | sí |
| `auth policy inspect` | Longitudes declaradas del formulario (sin red) | |
| `auth mfa test` | Primer factor, código incorrecto y código de prueba | sí |
| `auth sessions inspect` | HttpOnly, Secure y SameSite de las cookies | sí |
| `security rate-limit test` | Intentos incorrectos hasta observar bloqueo (con tope) | sí |
| `security csrf test` | Envío sin token, con token incorrecto y con token válido | sí |
| `security response-check` | Misma respuesta para cuenta existente e inexistente | sí |
| `requests history [--limite N]` | Ejecuciones registradas | |
| `requests inspect [--run ID]` | Resultados de una ejecución (por defecto, la última cerrada) | |
| `reports generate [--run ID]` | Informe en JSON, CSV, HTML y TXT | |
| `reports export --format json\|csv\|html\|txt [--run ID]` | Informe en un formato | |
| `reports verify` | Compara cada informe exportado con su huella registrada | |
| `test suites list` | Suites y procedimientos | |
| `test suites run <suite>` | Ejecuta cualquier suite (por ejemplo, `login-validation`) | sí |
| `targets list` / `targets add <origen>` | Objetivos permitidos | `add` sí |
| `accounts list` | Cuentas sintéticas y si sus variables están definidas | |

Opciones comunes: `--formulario <id>` (por defecto `login`, o `mfa` en `auth mfa test`),
`--objetivo <origen>` (obligatorio si hay varios objetivos), `--cuenta <id>` (repetible; sin él,
`synthetic-accounts` usa todas las cuentas configuradas, las demás suites la primera, y los
procedimientos una sola; los procedimientos aceptan un único `--cuenta`), `--json`.

## Resultados

Cada caso produce un resultado estructurado con código HTTP, duración, tipo de formulario,
identificador del caso, cuenta y motivo.

| Resultado | Significado |
|---|---|
| `PASS` | El servidor se comportó como se esperaba. |
| `FAIL` | El servidor se comportó de forma distinta a la esperada, o la respuesta es inconsistente. Es un hallazgo. |
| `BLOCKED` | Un control del servidor bloqueó la solicitud (429, 423 o un marcador de bloqueo). |
| `ERROR` | Fallo técnico: conexión, tiempo máximo, error 5xx o 404, o no poder leer la página del formulario (por ejemplo, el token CSRF). |
| `SKIPPED` | El caso no se ejecutó: presupuesto agotado, cancelación o un prerrequisito no cumplido. |

Códigos de salida de la CLI: `0` correcto y sin FAIL ni ERROR; `1` hay resultados FAIL o ERROR (o un
informe alterado o ausente en `reports verify`); `2` uso incorrecto o plan no válido; `3` autorización, sesión
o confirmación denegada; `4` error técnico, ejecución cancelada o interrupción.

## Control de la ejecución

- **Presupuesto**: al agotarse, los casos restantes quedan `SKIPPED` con su motivo.
- **Concurrencia y pausas**: aplicadas por el motor antes de cada petición.
- **Cancelación**: durante una ejecución, Ctrl+C solo solicita la cancelación. El motor no envía más
  peticiones, una pausa en curso termina de inmediato y la ejecución se cierra como `cancelada` con los
  resultados ya evaluados. Una petición en curso termina o expira según `timeout_s`. Ctrl+C no fuerza
  la salida: pulsarlo otra vez solo vuelve a pedir la cancelación. Fuera de una ejecución, Ctrl+C
  interrumpe la CLI con código 4.
- **Ejecución registrada**: se abre (con su evento de auditoría) antes de la primera petición y se
  cierra con sus resultados. Si el proceso se detiene a mitad, la ejecución queda sin cerrar (ver
  pendientes).
- **Plan validado antes de empezar**: objetivo, formulario, cuentas, variables de entorno y límites
  se comprueban antes de abrir la ejecución. Un plan no válido no deja rastro en la base de datos.

## Permisos y auditoría

- Registrar un objetivo, ejecutar pruebas y exportar informes son permisos de la plataforma
  aplicados por el guardián del núcleo. Por defecto, solo el rol `administrador` los tiene.
- Los roles `operador` y `auditor` pueden leer formularios, cuentas (sin valores), ejecuciones e
  informes verificados.
- Las operaciones críticas exigen confirmación explícita y reautenticación reciente.
- Eventos de auditoría: `pruebas.objetivo_registrado`, `pruebas.ejecucion_iniciada`,
  `pruebas.ejecucion_terminada` (con recuentos por resultado) y `pruebas.informe_exportado` (con la
  huella del informe). Ninguno contiene contraseñas, códigos MFA, cookies ni cuerpos de respuesta.

## Informes y verificación

Un informe contiene la cabecera de la ejecución, los totales por resultado, la metodología y cada
caso con su código, duración y motivo. **No contiene** contraseñas, códigos MFA, valores de cookies,
tokens CSRF ni cuerpos de respuesta: ninguno de esos datos se guarda.

- Cada exportación se guarda en `reports/pruebas/` como `<ejecución>-<identificador único>.<formato>`.
- CSV neutraliza las celdas que empiezan por `=`, `+`, `-`, `@`, tabulador o retorno de carro.
- HTML escapa todo el contenido.
- Cada exportación registra su SHA-256 y su tamaño. `reports verify` marca cada archivo como
  `correcto`, `alterado`, `faltante` o `fuera_de_carpeta`.

La huella comprueba integridad, no autoría. No es una firma digital.

## Base de datos

La migración 14 crea `http_targets`, `http_runs`, `http_results` y `http_exports`. Las tablas son
añadir-solo: disparadores impiden modificar o borrar objetivos, ejecuciones, resultados y
exportaciones ya guardados; una ejecución se cierra una sola vez; y solo acepta resultados mientras
está en curso.

## Servidor de laboratorio

`tests/laboratorio_http.py` es un servidor HTTP local (solo `127.0.0.1`, biblioteca estándar) con
dos cuentas sintéticas (la A tiene un segundo factor de prueba) y escenarios controlados: CSRF
exigido o permisivo, bloqueo tras varios fallos, mensajes que revelan si una cuenta existe, errores
500, latencia y cookies con o sin HttpOnly. Las pruebas de integración lo usan
para comprobar que el motor clasifica cada comportamiento como debe.

## Qué NO hace

- No sigue redirecciones. Cada petición la decide el motor, de modo que nunca se contacta un host no
  registrado.
- No prueba TLS (certificados, versiones, cifrados) ni cabeceras HTTP. Son pruebas de otra etapa.
- No genera contraseñas candidatas a partir de nombres, fechas, datos personales ni datos de
  personas reales. Las matrices usan valores fijos de prueba: la contraseña incorrecta es siempre la misma
  cadena (`clave-incorrecta-sintetica-0001`) y no se varía.
- No hace fuerza bruta, credential stuffing ni adivinación. El procedimiento de límite de frecuencia
  hace como mucho `max_intentos` (tope absoluto de 10) intentos incorrectos contra una cuenta
  sintética y se detiene en el primer bloqueo. No reintenta tras un bloqueo.
- No guarda contraseñas en configuración, base de datos, registros ni informes.

## Pendiente

Declarado, no implementado en esta etapa:

- **Windows no verificado**: los comandos `natxajo.cmd` y `natxajo.ps1` y la CLI no se han ejecutado
  en PowerShell 5.1, PowerShell 7 ni CMD. La salida depende de la codificación de la consola.
- **Interfaz gráfica**: la GUI no ofrece todavía las operaciones de pruebas. La CLI y el servicio
  comparten el motor y las reglas de autorización; la integración con la GUI queda pendiente.
- **Menú de la terminal**: no hay opciones de pruebas en el menú interactivo.
- **Interrupción forzada**: Ctrl+C solo pide la cancelación y no fuerza la salida. Si el proceso queda
  bloqueado fuera de una petición, hay que cerrarlo desde fuera.
- **Recuperación tras un fallo a mitad**: una ejecución interrumpida por la caída del proceso queda
  sin cerrar, y no hay comando de recuperación.
- **Exportación no atómica**: el archivo se escribe antes de registrar su huella. Un fallo entre
  ambos pasos puede dejar un archivo sin registro.
- **DNS**: el origen se comprueba por texto, sin resolver el host. Un nombre que cambie de dirección
  (DNS rebinding) no se detecta.
- **MFA real**: el segundo factor usa un código de prueba configurado en el entorno. No hay
  generación TOTP ni integración con un proveedor real.
- **Ámbito por empresa**: las ejecuciones son de la plataforma. No hay aislamiento de objetivos ni
  de ejecuciones por empresa.
- **Especificación alternativa**: la especificación `771fc6bf` también se titula etapa 5 (plugins,
  motor de anomalías, sesiones, informes y mantenimiento). No se ha aplicado.
