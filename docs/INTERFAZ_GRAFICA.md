# Interfaz gráfica local

`python main.py --gui` abre la interfaz gráfica de NATXAJO en el navegador. La sirve el propio
proceso, solo en `127.0.0.1`, en un puerto libre que elige el sistema. Con `--sin-navegador` solo
se imprime la dirección. Pulse Ctrl+C en la consola para detenerla.

```bash
python main.py --gui                  # abre el navegador
python main.py --gui --sin-navegador  # muestra la dirección sin abrir el navegador
```

`--sin-navegador` sin `--gui` es un error de uso y la aplicación no arranca.

## Decisión de diseño: web local y no ventana nativa

La interfaz no usa tkinter. Ese módulo no está disponible en el entorno de desarrollo y no está
garantizado en todas las instalaciones de Python. La alternativa es un servidor local de la
biblioteca estándar (`http.server`) que sirve HTML, CSS y JavaScript sin CDN, sin npm y sin
dependencias nuevas.

Consecuencias que conviene conocer:

- No es una ventana nativa: necesita un navegador y la pestaña debe seguir abierta mientras
  trabaja.
- El servidor atiende una petición cada vez. Es obligatorio: la conexión SQLite del núcleo solo
  puede usarse desde el hilo que la creó. Para un único operador local no supone un límite
  práctico.
- Todo el tráfico queda dentro de la máquina. No hay acceso desde otros equipos.

## Alcance

La interfaz no añade motores, servicios ni reglas de seguridad. Cada acción llama a una operación
que ya existía en el núcleo, con su mismo guardián de permisos, confirmación y reautenticación.

| Sección | Qué permite |
| --- | --- |
| Panel | Estado del sistema, plugins y módulos, sesiones activas, alertas de gravedad alta, actividad reciente y gráficos. |
| Auditoría | Eventos y evaluaciones con búsqueda, filtros, orden y detalle. Solo lectura. |
| Usuarios | Cuentas, roles y permisos efectivos. Solo lectura: las altas se hacen en la terminal. |
| Sesiones | Sesiones vigentes sin fichas ni huellas. Solo lectura: la revocación no está en la interfaz. |
| Plugins | Estado, versión, editor, confianza y versión anterior. Cuarentena, liberación, actualización desde carpeta y reversión, con confirmación y reautenticación. La instalación y la habilitación de plugins no están en la interfaz. |
| Módulos | Dependencias, permisos y problemas. Habilitar y deshabilitar, con confirmación y reautenticación. |
| Reportes | Historial, verificación de integridad, vista previa de la evaluación y exportación en JSON, CSV, HTML o TXT. |
| Eventos | Catálogo de tipos de evento y ocurrencias recientes. |
| Seguridad | Alertas y postura de la plataforma. |
| Mantenimiento | Diagnóstico de ocho comprobaciones, exportación JSON y plan de limpieza de temporales. Aplicar la limpieza exige confirmación y reautenticación. |
| Configuración | Preferencias visuales e información del sistema. |

## Preferencias

Las preferencias visuales se guardan en `config/interfaz.json`: tema (oscuro o claro), densidad,
animaciones, página de inicio, actualización automática, filas por página y avisos informativos.
Un archivo ilegible o con valores no válidos no impide arrancar: se usan los valores por defecto y
se muestra un aviso en Configuración. La actualización automática está en manual por defecto,
porque cada lectura queda auditada (ver más abajo).

## Primer uso

La interfaz no crea la cuenta de administrador. Si la instalación inicial no está completa, la
pantalla de acceso lo indica y pide completarla en la terminal.

## Seguridad

- **Transporte.** Escucha solo en 127.0.0.1. Rechaza un `Host` distinto de la dirección local, un
  `Origin` ajeno y las peticiones marcadas como de otro sitio (`Sec-Fetch-Site`). Limita el tamaño
  de las peticiones a 16 KiB y exige JSON en los cuerpos.
- **Sesión del navegador.** La cookie es `HttpOnly`, `SameSite=Strict` y `Path=/`. El token de la
  sesión de la plataforma se queda en el servidor y nunca llega al navegador. Cada POST exige una
  ficha CSRF que solo viaja en la respuesta JSON. La sesión rota al entrar y al salir.
- **Política de contenido.** `default-src 'none'; script-src 'self'; style-src 'self'`, sin
  scripts ni estilos en línea. Todos los datos se insertan como texto, nunca como HTML. Se añaden
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` y `Cache-Control: no-store`.
- **Autorización.** Cada lectura pasa por los servicios del núcleo. Una cuenta de empresa solo ve
  su empresa: pedir otra da 403 y pedir una cuenta ajena da 404. Las páginas de plataforma
  (Plugins, Módulos, Mantenimiento) no están disponibles para cuentas de empresa.
- **Operaciones críticas.** Requieren confirmación explícita y una reautenticación reciente, de
  cinco minutos. El inicio de sesión no cuenta como reautenticación. La interfaz muestra la
  confirmación antes de llamar al núcleo y pide la contraseña cuando el núcleo la exige.
- **Límite de sesiones.** Si la cuenta ya tiene el máximo de sesiones abiertas, la interfaz lo
  indica como tal. No se presenta como contraseña incorrecta.
- **Ruta de actualización de plugins.** La carpeta la escribe el operador. El núcleo la valida
  igual que en la terminal (firma, editor, versión y copia verificada) antes de cambiar nada.

## Auditoría y gravedad

- Cada lectura y cada acción pasa por el guardián del núcleo y queda registrada. Un refresco
  automático frecuente genera muchos registros: por eso el valor por defecto es manual.
- La gravedad de la columna y del panel es una regla fija de visualización, no un motor de
  detección. Alta: denegaciones, rechazos, cuarentenas, revocaciones, bloqueos de acceso y fallos
  de informes. Media: el resto de eventos de seguridad. Baja: eventos operativos.

## Verificación

- Pruebas automáticas: `tests/test_gui_*.py` y `tests/test_sesiones_listado.py`. Cubren el
  preprocesado de preferencias, la capa HTTP (Host, Origin, CSRF, cuerpos, rutas, cookies y
  sesiones), el alcance por empresa, las acciones con confirmación y reautenticación, el servidor
  y las opciones de arranque.
- `tests/test_gui_navegador.py` recorre las once páginas en Chromium y falla ante cualquier
  excepción, error de consola o carga que no termina. Se omite si Playwright o Chromium no están
  disponibles. Con `NATXAJO_CAPTURAS` apuntando a una carpeta, guarda capturas.
- Verificación visual: recorrido en Chromium headless con datos sintéticos, en escritorio (1440 px)
  y en móvil (390 px), sin desplazamiento horizontal.

## Limitaciones conocidas

- No se ha probado en Windows ni con la aplicación instalada desde un wheel en esa plataforma.
- No hay ventana nativa: el resultado depende del navegador del equipo.
- Sin revocación de sesiones, altas de usuarios ni cambios de cuenta desde la interfaz: esas
  operaciones siguen en la terminal. La instalación y la habilitación de plugins no existen todavía
  ni en la interfaz ni en la terminal.
- Los gráficos son SVG sencillos (dona y barras), sin librerías externas.
