# Ciclo de vida de los plugins: cuarentena, actualización y reversión

Estado: implementado y probado en Linux (etapa 4, fase 6). No probado en Windows.

Este documento describe lo que la plataforma hace con un plugin ya instalado. No ejecuta plugins:
habilitar un plugin solo registra su estado. Instalar y habilitar desde la terminal todavía no
existen; se hacen por la API del gestor (`PluginManager`).

## Estados

| Estado | Significado | Puede habilitarse |
|---|---|---|
| Deshabilitado | Paquete verificado y copiado al almacén. No hace nada | Sí, si cumple las reglas de habilitación |
| Habilitado | Copia almacenada verificada y dependencias habilitadas | — |
| En cuarentena | Su versión activa no puede habilitarse hasta liberarla | No |

Cada plugin tiene una versión activa y, como mucho, una versión anterior conservada en el almacén
(`storage/plugins/store/<id>/<versión>`). La versión anterior se usa para revertir.

## Permisos

| Operación | Permiso | Crítica | Notas |
|---|---|---|---|
| Ver el estado | `plugins:nucleo:estado:leer` | No | Solo plataforma. El auditor y el operador lo tienen |
| Poner en cuarentena | `plugins:nucleo:cuarentena:escribir` | No | Solo plataforma. Medida defensiva: no pide confirmación |
| Liberar la cuarentena | `plugins:nucleo:cuarentena:administrar` | Sí | Confirmación y reautenticación reciente |
| Actualizar una versión | `plugins:nucleo:version:administrar` | Sí | Confirmación y reautenticación reciente |
| Revertir a la versión anterior | `plugins:nucleo:version:administrar` | Sí | Confirmación y reautenticación reciente |

El rol `administrador` tiene todos los permisos. Ninguna cuenta de empresa ve estas operaciones: son
de plataforma. Cada intento denegado queda en la auditoría como `operation.denied`.

## Cuarentena

- Se aplica a la **versión activa** y se guarda con la clave (plugin, versión). Una cuarentena de la
  versión 0.1.0 no afecta a la 0.2.0.
- Pone el plugin en cuarentena y lo deshabilita, junto con los plugins habilitados que dependen de
  él (en cascada). Los dependientes se deshabilitan con el motivo `en cuarentena: <plugin>`.
- Motivo obligatorio de 1 a 200 caracteres, sin espacios al principio ni al final.
- Un plugin en cuarentena no se habilita, ni como dependencia de otro. Liberar la cuarentena no
  habilita el plugin: la habilitación es una operación aparte.
- Desinstalar un plugin en cuarentena es posible y elimina la cuarentena.

## Actualización

Actualizar instala una versión nueva de un plugin ya instalado. Pasa por la misma verificación que
una instalación (firma, integridad, API y versión del núcleo). Además, exige:

- que el plugin esté **deshabilitado**;
- que la versión sea **estrictamente mayor** que la activa (comparación MAJOR.MINOR.PATCH);
- que el paquete sea del **mismo editor** que la versión instalada;
- que el editor **no esté revocado**;
- que la versión **no esté ya en el almacén** (la versión anterior o una copia previa). Para volver a
  esa versión se usa la reversión.

Al actualizar, la versión activa pasa a ser la anterior conservada. La versión que había antes de
esa se retira del almacén: solo se conserva una versión anterior. El plugin queda deshabilitado.
La cuarentena de la versión anterior se elimina al retirarla; la de la versión activa no cambia.

## Reversión

Revertir **intercambia** la versión activa con la anterior. Revertir otra vez devuelve la versión
que se acaba de revertir, así que la reversión se deshace con otra reversión.

Antes de revertir se comprueban:

- que el plugin esté deshabilitado;
- que exista una versión anterior;
- que el editor no esté revocado;
- que la copia de la versión anterior verifique: firma e integridad, que su manifiesto corresponda a
  la versión del almacén y que su huella coincida con la registrada.

Si cualquiera falla, no cambia nada. La cuarentena no bloquea la reversión; bloquea la habilitación.
Por eso no se puede eludir revirtiendo a una versión en cuarentena: al intentar habilitarla, la
habilitación falla con el mensaje «está en cuarentena».

## Desinstalación

Desinstalar exige el plugin deshabilitado y sin dependientes. Elimina la cuarentena, la versión
anterior y las dos copias del almacén.

## Eventos de auditoría

| Evento | Categoría | Claves | Cuándo |
|---|---|---|---|
| `plugin.quarantined` | seguridad | `plugin`, `version`, `reason`, `username` | Al poner en cuarentena |
| `plugin.quarantine_released` | seguridad | `plugin`, `version`, `username` | Al liberar la cuarentena |
| `plugin.updated` | operativo | `plugin`, `from`, `to`, `publisher`, `username` | Al actualizar |
| `plugin.rolled_back` | operativo | `plugin`, `from`, `to`, `username` | Al revertir |
| `plugin.disabled` | operativo | `plugin`, `reason` | Al deshabilitar por cuarentena o revocación |
| `plugin.rejected` | seguridad | `source`, `reason` | Paquete que no supera la verificación |

El cambio de estado y su evento van en la misma transacción. Si la transacción falla, no queda ni el
cambio ni el evento.

## Base de datos

Migración 11, reversible:

- `plugin_quarantine (plugin_id, version)`: clave primaria compuesta. Una cuarentena por versión.
- `plugin_history (plugin_id)`: clave primaria simple. Una sola versión anterior por plugin.

La reversión de la migración 11 no necesita `DROP COLUMN`: no se comprueba la versión de SQLite.

## Terminal

Opciones 29 a 33, solo para cuentas de plataforma:

| Opción | Acción | Datos que pide |
|---|---|---|
| 29 | Estado de los plugins | — |
| 30 | Poner un plugin en cuarentena | identificador y motivo |
| 31 | Liberar la cuarentena (confirma) | identificador y confirmación |
| 32 | Actualizar desde una carpeta (confirma) | carpeta del paquete (puede ir entre comillas) y confirmación |
| 33 | Revertir a la versión anterior (confirma) | identificador y confirmación |

Las acciones críticas piden la confirmación en la terminal. Si la sesión no está reautenticada, el
servicio la rechaza con «operación crítica: reautentique la sesión» y no cambia nada.

## Límites conocidos

- **Sin ejecución.** Un plugin en cuarentena o deshabilitado no está en ejecución: no hay ejecución de
  plugins todavía. La cuarentena es un estado, no detiene procesos.
- **Una sola versión anterior.** No hay historial de versiones. Revertir dos veces seguidas solo
  alterna entre las dos.
- **Editor fijo.** Un plugin solo se actualiza con el mismo editor. Para cambiar de editor hay que
  desinstalar e instalar de nuevo.
- **Revisión de terceros.** La habilitación de un plugin de un editor de terceros sigue exigiendo una
  revisión aprobada de la versión concreta. Una actualización necesita una revisión nueva.
- **Copias bloqueadas en Windows.** Si Windows impide borrar la copia retirada (un programa tiene
  abierto un archivo), la operación termina con error de archivo bloqueado después de confirmar la
  base de datos. La copia queda en el almacén y esa versión no puede volver a instalarse hasta que se
  borre a mano. Este caso se comprobará en Windows (`docs/PRUEBAS_WINDOWS.md`, 5.4).
- **Autorización no verificada.** Las operaciones de cambio comprueban la sesión, el permiso y la
  reautenticación. No verifican que exista una autorización escrita para el cambio.
