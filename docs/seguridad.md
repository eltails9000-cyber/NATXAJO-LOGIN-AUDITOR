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

## Qué NO está implementado

- **Aislamiento de módulos.** No hay procesos separados, límites de recursos ni sandbox. Ningún
  módulo se ejecuta todavía. Cuando exista, la separación en carpetas o módulos no bastará: se
  documentará qué aislamiento real del sistema operativo se aplica.
- **Cifrado de datos sensibles.** La base de datos y las copias están en texto plano.
- **Control de acceso.** No hay usuarios ni roles (fase 7). Cualquiera con acceso al equipo
  puede ejecutar la plataforma.
- **Firmas de plugins e integridad de paquetes.** No hay plugins todavía.

## Permisos de archivos

Los datos de ejecución (`config/`, `storage/`) se crean con los permisos por defecto del sistema
operativo. En Windows conviene restringir el acceso a la carpeta del proyecto a la cuenta que
ejecuta la plataforma.
