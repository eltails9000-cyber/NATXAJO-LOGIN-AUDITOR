# Arquitectura

El núcleo (`kernel`) administra el ciclo de vida y registra servicios comunes. Las interfaces consumen los mismos servicios; la lógica no depende de terminal o escritorio.

## Límites de seguridad

No se implementarán pruebas de autenticación agresivas ni recolección de credenciales. Los módulos futuros deberán validar alcance autorizado y deberán aplicar límites conservadores.

## Versionado

Una sola versión se carga por ejecución. El núcleo no depende de una versión concreta. Los manifiestos deberán incorporar dependencias y compatibilidad antes de habilitar cargas distribuidas.
