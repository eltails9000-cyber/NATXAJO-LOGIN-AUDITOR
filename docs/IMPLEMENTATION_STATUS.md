# Estado de implementación

Este documento sustituye a `docs/roadmap.md`. Describe lo que existe en el código, no lo que
aparece en el documento maestro.

## Estados

- **VERIFICADO**: implementado y cubierto por pruebas automatizadas que pasan.
- **IMPLEMENTADO**: el código existe, pero no todas sus partes tienen pruebas o no se ha probado en
  el entorno objetivo (por ejemplo, Windows).
- **PARCIAL**: una parte está implementada y verificada; el resto de la fase figura en
  "pendiente".
- **PENDIENTE**: no existe en el código. No se declara como disponible.

## Resumen por fase

| Fase | Contenido | Estado |
|---|---|---|
| 1 | Inspección, diagnóstico, arquitectura y documentación | VERIFICADO (documentación en `docs/`) |
| 2 | Núcleo, ciclo de vida, contenedor de servicios, bus de eventos | VERIFICADO |
| 3 | Configuración, almacenamiento, migraciones, copias | PARCIAL |
| 4 | Gestor de versiones y cargador manual | PARCIAL |
| 5 | Sistema de módulos y dependencias | VERIFICADO (los módulos no ejecutan código) |
| 6 | Plugins: firma, integridad, editores, catálogo, revisión y ciclo de vida | PARCIAL |
| 7 | Seguridad, RBAC, sesiones y guardián de operaciones | PENDIENTE |
| 8 | Motor de automatización | PENDIENTE |
| 9 | Motor de auditoría defensiva | PENDIENTE |
| 10 | Aplicación de escritorio y terminal avanzada | PENDIENTE |
| 11 | Diagnósticos, informes y analítica | PENDIENTE |
| 12 | Mantenimiento, actualizaciones y recuperación | PENDIENTE |
| 13 | Pruebas integrales y distribución | PENDIENTE |

Pruebas automatizadas: 161 casos, con ruff y mypy en modo estricto sin errores.

## Fase 3: configuración y almacenamiento (PARCIAL)

- **Verificado:** configuración con esquema estricto, historial y restauración solo con
  autorización; base SQLite con migraciones transaccionales; auditoría; copias con SHA-256.
- **Pendiente:** perfiles predefinidos y personalizados, herencia y overrides, importación y
  exportación, comparación, copias incrementales, cifrado y control de acceso sobre la base de
  datos.
- **Diagnóstico:** el servicio de configuración no está conectado a la terminal, y varias claves del
  esquema (`logging.*`, `auditing.enabled`, `general.theme`, `general.locale`, `general.level`) no
  las usa ningún componente.

## Fase 4: versiones (PARCIAL)

- **Verificado:** canales, manifiestos validados, registro desde `versions/`, compatibilidad con el
  núcleo, carga manual, cambio, reversión e historial.
- **Pendiente:** ramas, etiquetas, snapshots, canales personalizados, comparación detallada,
  clonación, exportación, archivado, editor avanzado y asistente de creación.

## Fase 5: módulos (VERIFICADO)

- **Verificado:** manifiestos `modules/<id>/module.json` con permisos de catálogo, descubrimiento
  que aísla los módulos rotos, dependencias con detección de ausencias y ciclos, habilitación que
  activa antes las dependencias, deshabilitación protegida, estado persistente auditado y
  diagnóstico.
- **Pendiente:** ejecución de módulos (sin fase asignada), aplicación de permisos (depende de la
  fase 7), actualización y desinstalación.

## Fase 6: plugins (PARCIAL)

### Verificado

- **Criptografía:** Ed25519 en Python puro (`core/ed25519.py`), sin dependencias externas. Se
  comprueba con el vector de prueba 1 del RFC 8032, con firmas idénticas a las de la biblioteca
  `cryptography` en 40 casos, y con una firma generada por OpenSSL. Limitación documentada: no es
  de tiempo constante. Sirve para verificar datos públicos, no para firmar secretos.
- **Paquete:** carpeta con `plugin.json`, `integrity.json` (SHA-256 de cada archivo) y
  `signature.json` (firma Ed25519 de `integrity.json`). Como `integrity.json` incluye el hash de
  `plugin.json`, la firma protege también el manifiesto. Se rechazan enlaces simbólicos, archivos
  no declarados, archivos ausentes y archivos alterados.
- **Verificación antes de aceptar:** firma, editor registrado y no revocado, integridad,
  manifiesto, versión de API soportada y compatibilidad con el núcleo.
- **Editores de confianza:** clave pública Ed25519, nivel de confianza (`official`, `verified`,
  `third_party`, `revoked`).
- **Catálogo local:** `index.json` con el hash de cada paquete. Se comprueba que el índice
  coincide con el paquete y que la entrada corresponde a la versión pedida.
- **Revisión:** inventario de archivos (los ejecutables se señalan) y registro de decisiones con
  historial. Un plugin de editor `third_party` solo se habilita con una revisión aprobada.
- **Ciclo de vida:** instalar (deshabilitado), habilitar (habilita antes sus dependencias y
  vuelve a verificar la copia almacenada), deshabilitar (bloqueado si otro habilitado lo
  requiere), desinstalar (bloqueado si está habilitado o si otro instalado lo requiere).
- **Revocación:** revocar un editor deshabilita sus plugins y los que dependen de ellos,
  transitivamente.
- **Auditoría:** instalaciones, rechazos, habilitaciones, deshabilitaciones, desinstalaciones,
  revisiones y revocaciones quedan en `audit_events`.
- **Persistencia:** el estado sobrevive a un reinicio del núcleo.

### Pendiente

- **Ejecución de plugins.** No se ejecutan. Habilitar solo registra el estado. Hace falta un
  mecanismo de procesos aislados que aún no existe.
- **Repositorios remotos.** Solo hay catálogo local. No se implementa HTTPS.
- **Actualización de versiones.** Un plugin tiene una única versión instalada. Para cambiarla hay
  que desinstalarla primero.
- **Terminal.** No hay opciones de menú para plugins. Se gestionan desde la API del núcleo
  (`kernel.plugins`). Las opciones llegarán con el control de acceso de la fase 7.
- **Revisión automática.** El inventario clasifica por extensión. No detecta código malicioso ni
  sustituye la revisión humana.

## Fase 7: seguridad y RBAC (PENDIENTE)

Cuentas, roles, sesiones, permisos temporales y guardián de operaciones críticas. Hasta que exista,
cualquiera con acceso al equipo puede habilitar cualquier módulo o plugin instalado. Los permisos
declarados por módulos y plugins se validan en el formato `subsistema:modulo:recurso:accion`, pero no
se aplican.

## Otros pendientes

- Carpetas `powershell/` y `scripts/`: no se crean vacías. Se añadirán con su contenido.
- `launcher.ps1` no se ha probado en Windows. No hay PowerShell en el entorno de desarrollo.
- Instalación de dependencias (`pip install -e .[dev]`): no comprobada en este entorno.

## Cómo añadir una fase

1. Escribir las pruebas primero, en `tests/`.
2. Implementar solo lo necesario para que pasen.
3. Actualizar esta tabla, `CHANGELOG.md` y la documentación afectada.
4. No marcar nada como VERIFICADO si sus pruebas no pasan.
