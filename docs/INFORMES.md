# Informes

Estado: implementado y probado en Linux (etapa 4). Windows no verificado.

Un informe es la representación de una evaluación ya guardada (`docs/AUDITORIA_MOTOR.md`) en uno de
cuatro formatos. Exportar un informe lo escribe en disco, lo registra y deja constancia de su huella
para poder comprobarlo más tarde.

## Formatos

| Formato | Contenido | Notas de seguridad |
|---|---|---|
| `json` | Identificador del informe, metodología, versión de la plataforma, quién lo generó y la evaluación completa con sus hallazgos | Documento estructurado para otros sistemas |
| `csv` | Cabecera y una fila por hallazgo: `regla`, `titulo`, `ruta`, `estado`, `gravedad`, `valor_observado`, `valor_esperado`, `recomendacion` | Las celdas que empiezan por `=`, `+`, `-`, `@`, tabulador o retorno de carro se escriben con una comilla simple delante, para que una hoja de cálculo no las ejecute como fórmula |
| `html` | Página en español (`lang="es"`) con el resumen y la tabla de hallazgos | Todos los valores se escapan. No carga recursos externos ni scripts |
| `txt` | Texto plano con el título «INFORME DE AUDITORÍA DE CONFIGURACIÓN», el riesgo más alto, los hallazgos y la metodología | Pensado para leer sin herramientas |

Todos los formatos incluyen la **metodología**: la evaluación se hace sin conexión y ninguna solicitud
se envía al sistema evaluado. También incluyen la **referencia de autorización** que se registró con
la evaluación, la fecha de generación en ISO 8601 (UTC), la versión de la plataforma y el usuario que
exportó el informe.

No contienen contraseñas, tokens de sesión ni datos de cuentas. Los valores observados solo pueden
ser los que admite el esquema de la configuración (`docs/AUDITORIA_MOTOR.md`); las claves
desconocidas del documento de entrada no se repiten en ningún informe.

Cualquier otro formato se rechaza con «formato no soportado».

## Identificadores y nombres de archivo

- Cada informe tiene un identificador único (UUID v4) y la evaluación de origen tiene el suyo.
- El archivo se guarda en `reports/<empresa>/informe-<evaluación>-<informe>.<formato>`, por ejemplo
  `reports/acme/informe-<evaluación>-<informe>.json`.
- La empresa se valida con el mismo patrón que en el resto del núcleo. Un identificador como
  `../acme` se rechaza antes de tocar el disco.

## Exportación

`export(token, empresa, evaluación, formato)`:

1. Comprueba la sesión, el permiso `informes:nucleo:exportacion:escribir` y el ámbito de la empresa.
2. Carga la evaluación de esa empresa. Si no existe o pertenece a otra empresa, responde «evaluación
   no encontrada».
3. Genera el contenido en memoria. Si falla, no se escribe nada.
4. Escribe el archivo de forma atómica: primero un `.tmp` junto al destino y después el cambio de
   nombre. Un corte a mitad deja como máximo un `.tmp`, que el mantenimiento puede limpiar
   (`docs/MANTENIMIENTO.md`).
5. Inserta la fila en `report_exports` y el evento `report.exported` en **la misma transacción**.
6. Si el paso 5 falla, borra el archivo, no deja fila y registra `report.failed` con el motivo.

El motivo registrado es el mensaje del error de dominio, recortado a 200 caracteres. Para errores que
no son de dominio se registra un motivo genérico («error de escritura del informe»), para no guardar
rutas ni trazas internas en la auditoría.

Cada fila de `report_exports` guarda el identificador, la evaluación, la empresa, el formato, el
usuario, la ruta relativa, el SHA-256 y el tamaño en bytes. Las filas son inmutables: disparadores
`BEFORE UPDATE` y `BEFORE DELETE`.

## Historial

`history(token, empresa, límite)`: informes de una empresa, del más reciente al más antiguo. Sin
empresa (`None`) solo lo puede pedir la plataforma. El límite debe estar entre 1 y 500.

## Verificación

`verify(token, empresa)` compara cada fila de la empresa con su archivo (permiso de lectura de
informes). Estados posibles:

| Estado | Significado |
|---|---|
| `correcto` | El archivo existe y su SHA-256 y su tamaño coinciden con la fila |
| `alterado` | El archivo existe, pero su contenido o su tamaño han cambiado |
| `faltante` | Hay fila, pero el archivo no existe |
| `fuera_de_carpeta` | La ruta registrada apunta fuera de la carpeta de la empresa |
| `huerfano` | Hay un archivo en la carpeta de la empresa sin fila que lo registre |

La prueba `test_verification_detects_altered_missing_and_orphan_files` cubre `alterado`, `faltante` y
`huerfano`.

## Terminal

- Opción 23: exportar un informe (empresa, identificador de la evaluación, formato).
- Opción 24: historial de informes exportados. Una cuenta de la plataforma puede dejar vacía la empresa
  para ver todas.
- Opción 25: verificar los informes de una empresa. Muestra cada archivo con su estado y cuenta los
  problemas.

## Eventos

- `report.exported`: `run_id`, `report_id`, `format`.
- `report.failed`: `run_id`, `format`, `reason`.

## Pruebas

`tests/test_informes.py` (16 casos): contenido de cada formato, neutralización de fórmulas en CSV,
escape en HTML, exportación con permisos y aislamiento entre empresas, fallo a mitad de exportación sin
archivo ni fila, verificación de los cinco estados y rutas con espacios y caracteres Unicode.

## Firma de los informes

Cada informe nuevo se firma con Ed25519 y la firma se guarda en un archivo `<informe>.firma.json`
junto al informe. La clave `firma_informes.clave` está en la carpeta de almacenamiento. Se crea una
vez, nunca se sobrescribe y tiene permisos 0600 en sistemas POSIX; en Windows no hay una protección
equivalente.

La verificación distingue cuatro estados:

- `firmado_valido`: la firma corresponde al informe y a la clave de esta instalación.
- `sin_firma`: informe exportado antes de la firma. Se comprueba su huella, pero no tiene firma.
- `firma_no_valida`: el informe cambió, la firma es de otra clave o el archivo de firma no encaja.
- `no_legible`: el informe o su firma no se pueden leer.

Límite: la clave vive en el mismo equipo que los informes. La firma demuestra que nadie modificó el
informe sin acceso a esa clave; no demuestra nada frente a quien controle la máquina.

## Pendiente

- Formato PDF.
- Informes de auditorías activas: no existen porque el motor no hace pruebas activas.
- Firma con clave externa a la máquina, que daría una garantía frente al propio equipo.
