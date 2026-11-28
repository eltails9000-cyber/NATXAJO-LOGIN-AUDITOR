"""Motor de pruebas HTTP y de formularios de autenticación.

Solo opera contra servidores registrados como objetivos permitidos y con cuentas sintéticas. El
paquete depende de `core` y `storage`; las operaciones llegan protegidas por un OperationGate, de
modo que la comprobación de permisos vive en `security` y no se duplica aquí. Ver
docs/PRUEBAS_HTTP.md.
"""
