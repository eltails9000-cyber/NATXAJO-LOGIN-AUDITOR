"""Interfaz gráfica local: un servidor en 127.0.0.1 que sirve una aplicación web estática.

No ejecuta lógica de auditoría. Todas sus lecturas y acciones pasan por los servicios del núcleo y
por el guardián de operaciones.
"""

from natxajo_auditor.interfaces.gui.server import GuiServer, run_gui

__all__ = ["GuiServer", "run_gui"]
