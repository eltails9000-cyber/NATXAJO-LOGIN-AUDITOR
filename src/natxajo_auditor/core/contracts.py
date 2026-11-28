"""Contratos públicos entre subsistemas.

Los subsistemas de módulos y plugins dependen de estos tipos y no de las implementaciones de
security/. Así no importan la seguridad concreta y pueden probarse con un guardián sustituto.

Las constantes de este módulo son valores que varios subsistemas comparten. Se definen aquí
una sola vez y cada subsistema las importa.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, TypeVar

PLATFORM_COMPANY = "plataforma"
SCOPE_DENIED = "la operación pertenece a otra empresa"
APPROVE_PERMISSION = "seguridad:nucleo:permiso:aprobar"

# Permisos de la etapa 4. La terminal y los servicios los comparten: se definen una sola vez.
AUDIT_READ_PERMISSION = "auditoria:nucleo:evaluacion:leer"
AUDIT_RUN_PERMISSION = "auditoria:nucleo:evaluacion:ejecutar"
REPORT_READ_PERMISSION = "informes:nucleo:exportacion:leer"
REPORT_EXPORT_PERMISSION = "informes:nucleo:exportacion:escribir"
DIAGNOSTIC_PERMISSION = "mantenimiento:nucleo:diagnostico:leer"
CLEANUP_PERMISSION = "mantenimiento:nucleo:limpieza:ejecutar"
# Reencola un evento fallido. Solo administradores por defecto: un evento que vuelve a entregarse
# puede disparar efectos en los consumidores que aún no lo recibieron.
EVENT_REQUEUE_PERMISSION = "mantenimiento:nucleo:eventos:ejecutar"
# Restaura una copia de la configuración: sustituye ajustes que afectan a todo el sistema.
CONFIGURATION_RESTORE_PERMISSION = "configuracion:nucleo:restauracion:ejecutar"

# Plugins: estado (lectura), cuarentena (escribir, no crítica: es una medida defensiva), liberar
# la cuarentena y cambiar de versión (ambas críticas: cambian qué código puede habilitarse).
PLUGIN_READ_PERMISSION = "plugins:nucleo:estado:leer"
PLUGIN_QUARANTINE_PERMISSION = "plugins:nucleo:cuarentena:escribir"
PLUGIN_QUARANTINE_RELEASE_PERMISSION = "plugins:nucleo:cuarentena:administrar"
PLUGIN_VERSION_PERMISSION = "plugins:nucleo:version:administrar"

# Lectura de pantallas de la interfaz gráfica. Cada consulta pasa por el guardián.
EVENT_READ_PERMISSION = "auditoria:nucleo:evento:leer"
ACCOUNT_READ_PERMISSION = "seguridad:nucleo:cuenta:leer"
# Cambio de roles de una cuenta. Solo la plataforma (ver SecurityService.change_roles).
ACCOUNT_ADMIN_PERMISSION = "seguridad:nucleo:cuenta:administrar"
SESSION_READ_PERMISSION = "seguridad:nucleo:sesion:leer"
COMPANY_READ_PERMISSION = "seguridad:nucleo:empresa:leer"
MODULE_READ_PERMISSION = "modulos:nucleo:modulo:leer"
MODULE_EXECUTE_PERMISSION = "modulos:nucleo:modulo:ejecutar"
# Pruebas HTTP de autenticación. Registrar un objetivo y ejecutar pruebas activas son críticos:
# exigen confirmación y reautenticación. Leer resultados y exportar informes no lo son.
HTTP_TARGET_PERMISSION = "pruebas:nucleo:objetivo:administrar"
HTTP_RUN_PERMISSION = "pruebas:nucleo:ejecucion:ejecutar"
HTTP_READ_PERMISSION = "pruebas:nucleo:resultado:leer"
HTTP_EXPORT_PERMISSION = "pruebas:nucleo:informe:escribir"

T = TypeVar("T")


class OperationGate(Protocol):
    """Puerta de operaciones: identifica al actor y ejecuta una operación con autorización.

    La implementación de producción es security.guard.OperationGuard. Sin empresa indicada, la
    operación es de plataforma.
    """

    def username_for(self, token: str) -> str:
        """Cuenta de una sesión válida. Lanza una excepción si la sesión no es válida."""
        ...

    def run(
        self,
        token: str,
        permission: str,
        operation: Callable[[], T],
        *,
        confirmed: bool = False,
        company_id: str | None = None,
    ) -> T:
        """Ejecuta operation solo si la sesión tiene el permiso y se cumple el ámbito."""
        ...
