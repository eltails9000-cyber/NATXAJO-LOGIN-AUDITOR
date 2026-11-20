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

## Qué NO está implementado

- **Aislamiento de módulos.** No hay procesos separados, límites de recursos ni sandbox. Ningún
  módulo se ejecuta todavía. Los permisos que un módulo declara no se aplican: hasta que exista
  RBAC (fase 7), cualquier usuario con acceso a la plataforma puede habilitar cualquier módulo
  instalado. Cuando exista, la separación en carpetas o módulos no bastará: se
  documentará qué aislamiento real del sistema operativo se aplica.
- **Cifrado de datos sensibles.** La base de datos y las copias están en texto plano.
- **Control de acceso.** No hay usuarios ni roles (fase 7). Cualquiera con acceso al equipo
  puede ejecutar la plataforma.
- **Ejecución de plugins.** Habilitar un plugin solo registra su estado. No hay procesos separados
  ni límites de recursos. Cuando exista ejecución, se documentará el aislamiento real del sistema
  operativo que se aplica.

## Permisos de archivos

Los datos de ejecución (`config/`, `storage/`) se crean con los permisos por defecto del sistema
operativo. En Windows conviene restringir el acceso a la carpeta del proyecto a la cuenta que
ejecuta la plataforma.
