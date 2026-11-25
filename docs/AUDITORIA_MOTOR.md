# Motor de auditoría

Estado: implementado y probado en Linux (etapa 4). Windows no verificado.

## Qué hace y qué no hace

El motor evalúa **una configuración declarada** en un documento JSON contra 17 reglas de seguridad
de autenticación. Trabaja sin conexión: no envía solicitudes, no abre puertos y no prueba
credenciales. Lee el documento que entrega la persona auditora, lo valida, aplica las reglas y guarda
el resultado.

No hace (y no hará sin un registro de alcance y autorización, pendiente):

- Pruebas activas contra un sistema en ejecución: TLS, cabeceras HTTP o formularios de inicio de
  sesión. Por eso no hay `auditing` que llame a la red.
- Fuerza bruta, adivinación de contraseñas, credential stuffing, evasión de controles ni recolección
  de credenciales reales. Ver `docs/seguridad.md`.

La autorización escrita se **registra** con la evaluación (referencia obligatoria), pero la
plataforma **no la verifica**: no puede comprobar un documento firmado fuera del sistema.

## Documento de entrada (esquema v1)

- Formato JSON estricto: sin claves duplicadas, sin `NaN` ni `Infinity`, con límite de anidamiento.
  Codificación UTF-8, con o sin BOM. Tamaño máximo: 256 KiB.
- La raíz debe tener `"esquema": 1`. Una raíz o una sección con claves desconocidas se rechazan. El
  error indica cuántas claves sobran y **nunca repite su contenido**.
- Un valor `null` significa «declarado pero sin configurar» y **cuenta como fallo**. Una sección
  ausente hace que sus reglas sean **no evaluables**, no fallos.
- Los valores de texto solo pueden ser los que admite el esquema. Por ejemplo, `algoritmo` admite
  `argon2id`, `bcrypt`, `scrypt`, `pbkdf2-sha256`, `pbkdf2-sha1`, `sha1`, `sha256` y `md5`. Los
  cuatro últimos existen en el esquema para poder declararlos, y la regla AUT-003 los marca como
  fallo.

| Sección | Campo | Tipo y límites |
|---|---|---|
| `contrasenas` | `longitud_minima` | entero, 1 a 256 |
| `contrasenas` | `complejidad` | booleano |
| `contrasenas` | `algoritmo` | texto de la lista anterior |
| `bloqueo` | `intentos_maximos` | entero, 0 a 1000 |
| `bloqueo` | `duracion_minutos` | entero, 0 a 100000 |
| `bloqueo` | `mensaje_generico` | booleano |
| `sesiones` | `inactividad_minutos` | entero, 1 a 10080 |
| `sesiones` | `absoluta_horas` | entero, 1 a 8760 |
| `sesiones` | `simultaneas_maximas` | entero, 1 a 1000 |
| `cookies` | `secure`, `http_only` | booleanos |
| `cookies` | `same_site` | `Lax`, `Strict` o `None` |
| `transporte` | `tls_minimo` | `1.0`, `1.1`, `1.2` o `1.3` |
| `transporte` | `hsts` | booleano |
| `mfa` | `administradores_obligatorio` | booleano |
| `frecuencia` | `habilitado` | booleano |
| `frecuencia` | `solicitudes_por_minuto` | entero, 1 a 100000 |

Ejemplo mínimo de documento completo: `tests/auditoria_datos.py` (`GOOD` cumple las 17 reglas y
`WEAK` no cumple ninguna).

## Reglas

Generadas desde el catálogo de `src/natxajo_auditor/auditing/catalog.py`. La columna «Sobrescribible»
indica el intervalo permitido para `overrides`; las demás reglas no admiten sobrescritura.

| Id | Título | Ruta | Criterio | Gravedad | Sobrescribible |
|---|---|---|---|---|---|
| AUT-001 | Longitud mínima de contraseña | `contrasenas.longitud_minima` | al menos 12 | alto | 8 a 128 |
| AUT-002 | Requisitos de complejidad de contraseña | `contrasenas.complejidad` | activado | medio | — |
| AUT-003 | Algoritmo de almacenamiento de contraseñas | `contrasenas.algoritmo` | argon2id, bcrypt, pbkdf2-sha256 o scrypt | critico | — |
| AUT-004 | Bloqueo tras intentos fallidos | `bloqueo.intentos_maximos` | entre 1 y 10 | medio | — |
| AUT-005 | Duración del bloqueo temporal | `bloqueo.duracion_minutos` | al menos 5 | medio | 1 a 1440 |
| AUT-006 | Mensaje genérico durante el bloqueo | `bloqueo.mensaje_generico` | activado | alto | — |
| AUT-007 | Caducidad de sesión por inactividad | `sesiones.inactividad_minutos` | como máximo 15 | medio | 1 a 240 |
| AUT-008 | Caducidad absoluta de sesión | `sesiones.absoluta_horas` | como máximo 8 | medio | 1 a 168 |
| AUT-009 | Sesiones simultáneas por cuenta | `sesiones.simultaneas_maximas` | entre 1 y 5 | bajo | — |
| AUT-010 | Cookies de sesión solo por HTTPS | `cookies.secure` | activado | alto | — |
| AUT-011 | Cookies de sesión sin acceso desde scripts | `cookies.http_only` | activado | alto | — |
| AUT-012 | Atributo SameSite de las cookies | `cookies.same_site` | Lax o Strict | medio | — |
| AUT-013 | Versión mínima de TLS | `transporte.tls_minimo` | 1.2 o 1.3 | alto | — |
| AUT-014 | Cabecera HSTS | `transporte.hsts` | activado | medio | — |
| AUT-015 | Segundo factor para administradores | `mfa.administradores_obligatorio` | activado | alto | — |
| AUT-016 | Control de frecuencia de intentos | `frecuencia.habilitado` | activado | alto | — |
| AUT-017 | Límite de solicitudes de autenticación por minuto | `frecuencia.solicitudes_por_minuto` | como máximo 60 | bajo | 1 a 10000 |

Los textos de cada regla (título, criterio y recomendación) están en español en el catálogo.

## Perfiles

- `completo`: las 17 reglas (gravedad mínima `bajo`).
- `critico`: las reglas de gravedad `alto` o `critico`: AUT-001, AUT-003, AUT-006, AUT-010, AUT-011,
  AUT-013, AUT-015 y AUT-016 (8 reglas).

## Resultado

Cada regla produce un hallazgo con uno de tres estados:

- `cumple`: el valor observado satisface el criterio.
- `no_cumple`: el valor existe y no satisface el criterio, o el campo está en `null`.
- `no_evaluable`: la sección o el campo no existen en el documento.

El **riesgo** de la evaluación es la gravedad más alta entre los hallazgos `no_cumple`, o `ninguno`
si no falla ninguna regla. Los valores posibles son `ninguno`, `bajo`, `medio`, `alto` y `critico`.

El **resumen** cuenta cumplidas, no cumplidas y no evaluables. La **huella** de la configuración es
el SHA-256 de su forma canónica: dos documentos con el mismo contenido tienen la misma huella aunque
cambien el orden de sus claves o el espaciado.

## Sobrescrituras

Solo las reglas de la tabla con intervalo pueden sobrescribirse, y solo dentro de ese intervalo. Una
sobrescritura cambia el criterio de la regla (por ejemplo, exigir 14 caracteres en AUT-001), se
registra en la evaluación y cambia el texto «al menos N» del valor esperado. En la terminal solo se
aceptan enteros (formato `REGLA=valor`, separados por comas).

## Ejecución y registro

- `run_document` evalúa un documento ya leído; `run_file` lee el archivo **después** de comprobar el
  permiso. El archivo debe ser un fichero regular: los enlaces simbólicos se rechazan.
- Cada evaluación se guarda en `audit_runs` (una fila) y `audit_findings` (una por regla), en la misma
  transacción que el evento `audit.run_recorded`. Si la transacción falla, no queda nada.
- Las filas son inmutables: disparadores `BEFORE UPDATE` y `BEFORE DELETE` las protegen. Quien
  quite los disparadores de la base puede alterar la evaluación, y la carga la detecta: si el estado
  de un hallazgo no corresponde a su valor observado, `load` lanza `StorageError` («registro de
  evaluación inconsistente»). La detección se prueba en `test_a_tampered_finding_is_detected_when_the_run_is_loaded`.
- La validación de resultados (`validate_run`) comprueba antes de guardar: identificadores UUID v4,
  formato de la empresa, longitud y caracteres de la referencia, formato de la huella, orden de las
  fechas, que haya exactamente una regla por cada regla del perfil, y que la gravedad, el criterio y
  el estado coincidan con el valor observado.

## Permisos y empresas

| Operación | Permiso | Ámbito |
|---|---|---|
| Evaluar | `auditoria:nucleo:evaluacion:ejecutar` | empresa (la plataforma puede evaluar para cualquiera) |
| Historial, ver una evaluación | `auditoria:nucleo:evaluacion:leer` | empresa; sin empresa, solo la plataforma |
| Catálogo de reglas | solo sesión válida | público |

Una evaluación de otra empresa responde igual que una inexistente («evaluación no encontrada»), para
no revelar qué identificadores existen. El rol `auditor` puede leer pero no evaluar; el rol
`operador` no tiene el permiso de evaluación.

## Terminal

- Opción 20: evaluar un archivo. Una cuenta de la plataforma indica la empresa; una cuenta de empresa
  usa la suya. Admite rutas entre comillas, rutas con espacios y caracteres especiales.
- Opción 21: historial. Opción 22: una evaluación con todos sus hallazgos y su huella.
- Opción 28: catálogo de reglas.

## Eventos

- `audit.run_recorded`: `run_id`, `profile`, `passed`, `failed`, `not_evaluable`, `risk`.

## Pendiente

- Pruebas activas (TLS, HTTP, formularios). Requieren un registro de alcance y autorización.
- Verificación criptográfica de la autorización escrita.
- Perfiles definidos por la persona usuaria: hoy solo `completo` y `critico`.
- Exportación a formatos de informe: ver `docs/INFORMES.md`.
