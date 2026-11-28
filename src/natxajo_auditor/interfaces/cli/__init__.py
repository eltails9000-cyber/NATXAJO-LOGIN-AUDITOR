"""CLI de línea de comandos: `natxajo <grupo> <acción>`.

Usa el mismo motor y las mismas reglas de autorización que la GUI y la terminal: cada operación
pasa por el guardián del núcleo. Esta capa solo lee argumentos, pide la contraseña, presenta
resultados y traduce errores a códigos de salida. No importa seguridad ni pruebas directamente.

El punto de entrada es `natxajo_auditor.interfaces.cli.app` (ejecutar_cli, es_comando_cli). Este
paquete no reexporta nada para evitar ciclos entre el paquete y sus módulos.
"""
