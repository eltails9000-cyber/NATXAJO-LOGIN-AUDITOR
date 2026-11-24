# Procedimiento de pruebas en Windows 10 y 11

Estado: **pendiente de ejecución.** Este documento describe cómo verificar la plataforma en Windows.
Ningún resultado de esta página se ha obtenido en Windows. Hasta que se registre una ejecución con
el formulario de la sección 6, la compatibilidad con Windows no está verificada.

El procedimiento separa tres niveles, y cada resultado debe anotarse en el nivel que corresponde:

- **Automatizado:** `pytest`, Ruff y mypy. Se ejecutan igual en Linux y en Windows.
- **Lanzador y terminal:** comprobaciones manuales de `launcher.ps1` y de la interacción real.
- **Específico de Windows:** bloqueo de archivos, codificación de la consola y permisos.

## 1. Entornos a cubrir

| Entorno | Versión mínima | Versión de Python |
|---|---|---|
| Windows 10 | 22H2 | 3.11 y 3.13 |
| Windows 11 | 23H2 | 3.11 y 3.13 |

Python debe instalarse desde python.org o con `winget`. Anote la build exacta de Windows con
`winver` y la versión de SQLite con el comando de la sección 2.

## 2. Preparación

Abra PowerShell (no como administrador) y ejecute:

```powershell
# Versión de Windows
(Get-ComputerInfo).WindowsProductName
(Get-ComputerInfo).WindowsVersion

# Política de ejecución efectiva (anote el valor de CurrentUser)
Get-ExecutionPolicy -List

# Python disponible
py -0p
```

Obtenga el código en una carpeta con espacios y caracteres no ASCII, para probar rutas:

```powershell
New-Item -ItemType Directory -Force -Path "C:\Pruebas\natxajo árbol con espacios" | Out-Null
Set-Location "C:\Pruebas\natxajo árbol con espacios"
git clone https://github.com/eltails9000-cyber/natxajo-login-auditor .
git checkout etapa-2-multiempresa-instalador-bus
git log --oneline -1   # debe mostrar 9a371c7 o un commit posterior
```

Cree un entorno virtual para cada versión de Python. Use el ejecutable directamente para no depender
de la política de ejecución al activar el entorno:

```powershell
py -3.11 -m venv .venv311
.\.venv311\Scripts\python.exe -m pip install --upgrade pip
.\.venv311\Scripts\python.exe -m pip install -e ".[dev]"
```

Compruebe la versión de SQLite que usa ese Python:

```powershell
.\.venv311\Scripts\python.exe -c "import sqlite3, sys; print(sys.version); print(sqlite3.sqlite_version)"
```

La reversión de las migraciones 6 y 8 necesita SQLite 3.35 o posterior. Anote la versión.

## 3. Nivel automatizado

Ejecute las comprobaciones desde la carpeta del proyecto:

```powershell
.\.venv311\Scripts\python.exe -m pytest -p no:cacheprovider
.\.venv311\Scripts\python.exe -m ruff check .
.\.venv311\Scripts\python.exe -m ruff format --check .
.\.venv311\Scripts\python.exe -m mypy --strict src
```

Resultado esperado en la rama `etapa-3-kernel-composicion`: 325 pruebas aprobadas, sin errores de
Ruff ni de mypy. Estas cifras son las de Linux con Python 3.13 y 3.11.
Repita con Python 3.13 (`py -3.13 -m venv .venv313`). Si una prueba falla solo en Windows, no la
marque como fallo de código sin antes revisar la causa: anótela con el mensaje completo.

Compruebe que las pruebas no dejan archivos ni bloqueos en la carpeta del proyecto:

```powershell
Get-ChildItem -Recurse -Force -File -Filter "*.db" | Where-Object { $_.FullName -notlike "*\.venv*" }
```

Anote las bases de datos que aparezcan. Las pruebas usan directorios temporales, así que no debe
aparecer ninguna fuera de `storage\`, y `storage\` no debe existir tras ejecutar solo `pytest`.

## 4. Lanzador y terminal

**4.1 Política de ejecución.** Con la política por defecto de un equipo cliente, `.\launcher.ps1`
puede no ejecutarse. Pruebe primero sin cambiar nada:

```powershell
.\launcher.ps1 --version
```

Anote si aparece el error de «ejecución de scripts deshabilitada». Después, con el comando del
README que no cambia la configuración del equipo:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\launcher.ps1 --version
```

Debe mostrar la versión y salir con código 0. Compruébelo con `$LASTEXITCODE`.

**4.2 Búsqueda de Python.** Con solo Python 3.13 instalado, el lanzador debe seleccionarlo. Con
solo Python 3.10 instalado, debe fallar con el mensaje de «Python 3.11 o posterior». Pruebe ambos
casos si el equipo lo permite.

**4.3 Primer arranque.** Con una carpeta limpia (sin `storage\` ni `config\`):

1. Ejecute `powershell -NoProfile -ExecutionPolicy Bypass -File .\launcher.ps1`.
2. Debe mostrarse un código de instalación una sola vez.
3. Pruebe un código erróneo cinco veces. Debe cortarse en el quinto intento.
4. Complete la instalación con el código correcto. Cierre la terminal.
5. Vuelva a abrir: no debe volver a pedir la instalación. Compruebe que `storage\natxajo.db` existe.
6. Inicie sesión, cree una empresa, cree una cuenta en ella y solicite un permiso temporal.
7. Revise la auditoría. Las operaciones de la empresa deben verse solo desde la plataforma o desde
   esa empresa.

**4.4 Interrupciones.** Durante una operación de la terminal, pulse Ctrl+C. Anote si aparece un
rastreo de error (es lo esperado, ver A-13 en `docs/AUDITORIA_ETAPA_2.md`). Después, reabra la
terminal y compruebe que la base no quedó dañada: vuelva a arrancar el lanzador como en el paso 4.3
y verifique que la instalación y las cuentas siguen ahí.

**4.5 Alias de la Microsoft Store.** Si el equipo tiene los alias de `python.exe` de la Microsoft
Store y ningún Python instalado, el lanzador debe fallar con el mensaje «no se encontró Python 3.11 o
posterior» y salir con código 1, sin abrir la Store ni quedarse esperando. Compruébelo con
`$LASTEXITCODE`.

**4.6 Rutas y argumentos.** Copie el proyecto a una carpeta con espacios y acentos (por ejemplo
`C:\Pruebas Ñandú\proyecto`) y ejecute el lanzador con `--version`. Debe funcionar y salir con
código 0. Con un `main.py` ausente, debe mostrar «no se encuentra main.py» y salir con código 1.

**4.7 Terminal de la etapa 4.** Con una cuenta administradora:

1. Evalúe un archivo JSON con la ruta entre comillas (opción 20).
2. Exporte el informe en los cuatro formatos (opción 23) y verifíquelos (opción 25).
3. Cree un archivo `*.tmp` antiguo en `config\` y ejecute la limpieza (opción 27). Primero debe
   mostrar el plan y pedir confirmación. Sin reautenticación reciente, la operación debe rechazarse
   y el archivo debe seguir ahí.
4. Abra los cuatro informes y compruebe que se leen bien en Windows.

**4.8 Plugins (opciones 29 a 33).** Pendiente de ejecución en Windows. La terminal no instala plugins
todavía: instale antes un paquete firmado con la API. Con una cuenta de plataforma administradora:

1. Consulte el estado (opción 29). El plugin debe aparecer deshabilitado, con su editor.
2. Ponga el plugin en cuarentena (opción 30) con un motivo. No debe pedir confirmación.
3. Intente liberar la cuarentena (opción 31) sin reautenticar. Debe rechazarse con «operación
   crítica: reautentique la sesión», y la cuarentena debe seguir.
4. Reautentique (opción 17), libere la cuarentena (opción 31) y responda «sí».
5. Actualice desde una carpeta con espacios y acentos, con la ruta entre comillas (opción 32), usando
   un paquete de versión mayor firmado por el mismo editor. El plugin debe quedar deshabilitado y con
   la versión anterior conservada.
6. Revierta (opción 33) respondiendo «no»: no debe cambiar nada. Repita respondiendo «sí»: debe volver
   a la versión anterior.
7. Anote si la copia retirada se borra de `storage\plugins\store\`. Si un programa tiene abierto un archivo de la
   copia, aplique el caso 5.4 y anote el mensaje exacto.

## 5. Específico de Windows

**5.1 Bloqueo de archivos.** Abra `config\app.json` en el Bloc de notas mientras la plataforma
guarda la configuración. Anote si la operación falla con un error claro y si el archivo queda
intacto (sin mitad de escritura). Cierre el Bloc de notas y repita.

**5.2 Codificación de la consola.** Compruebe la salida redirigida directamente, con caracteres del español y un símbolo fuera de
cp1252:

```powershell
.\.venv311\Scripts\python.exe -c "print('ñ á é ü → ✓')" > salida.txt
Get-Content .\salida.txt -Encoding Byte | Select-Object -First 20
```

Anote si el comando termina con `UnicodeEncodeError`. Repita con `$env:PYTHONUTF8 = "1"` en la
misma sesión y anote la diferencia. Después, ejecute el lanzador con la salida redirigida y revise
que los mensajes en español no se corrompen. Este caso es A-14.

**5.3 Permisos de la carpeta.** Revise qué cuentas pueden leer la base de datos y las copias:

```powershell
icacls .\storage
```

Anote si otras cuentas locales tienen acceso. La documentación recomienda restringir la carpeta del
proyecto a la cuenta que ejecuta la plataforma. Este paso no cambia nada: solo registra el estado.

**5.4 Plugins y copias bloqueadas.** Con un archivo de un plugin abierto por otro programa, intente
instalar o desinstalar ese plugin. Anote si la operación falla de forma cerrada (la plataforma queda
sin cambios) o si deja restos. Este caso es A-12.

**5.5 Ejecución repetida.** Ejecute `pytest` dos veces seguidas. Anote si aparece algún
`PermissionError` al limpiar directorios temporales.

## 6. Formulario de resultados

Copie este bloque y rellénelo con los resultados reales. No rellene un campo que no haya observado.

```text
Fecha de ejecución:
Persona que ejecuta:
Commit probado (git log -1):
Windows (WindowsProductName y WindowsVersion):
Python (versión y ruta):
SQLite (sqlite3.sqlite_version):
Política de ejecución efectiva:

Automatizado
- pytest:                       ___ aprobadas, ___ fallidas
- ruff check:                   sin errores / errores: ___
- ruff format --check:          sin cambios pendientes / ___
- mypy --strict src:            sin errores / errores: ___

Lanzador y terminal
- launcher sin Bypass:          funciona / falla con: ___
- launcher con Bypass:          funciona / falla con: ___
- Primer arranque y cinco intentos: ___
- Instalación y reapertura:     ___
- Empresa, cuenta, permiso, auditoría: ___

Específico de Windows
- Bloqueo de config\app.json (5.1):  ___
- Salida redirigida (5.2):           ___
- Permisos de storage (5.3):         ___
- Plugin con archivo bloqueado (5.4): ___
- pytest repetido (5.5):             ___

Incidencias y capturas de los mensajes exactos:
```

## 7. Plantilla opcional de CI

Esta plantilla no está añadida al repositorio. Si el equipo decide ejecutar estas comprobaciones en
cada commit, puede guardarla como `.github/workflows/windows.yml`. Antes, pruébela en una rama: no
se ha ejecutado.

```yaml
name: windows
on: [pull_request]
jobs:
  test:
    runs-on: windows-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: python -m pip install -e ".[dev]"
      - run: python -c "import sqlite3; print(sqlite3.sqlite_version)"
      - run: python -m pytest -p no:cacheprovider
      - run: python -m ruff check .
      - run: python -m ruff format --check .
      - run: python -m mypy --strict src
```

Un resultado verde en esa plantilla es prueba automatizada en Windows. No sustituye a las
comprobaciones manuales de las secciones 4 y 5, que requieren interacción real con el lanzador y
la consola.
