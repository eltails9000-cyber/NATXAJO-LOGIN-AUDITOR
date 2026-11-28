import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from natxajo_auditor.core import ed25519
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.plugins.package import build_package
from tests.laboratorio_http import LIMITES_PRUEBA, entorno_de_prueba, escribir_configuracion

PLUGIN_SECRET = bytes(range(1, 33))
PLUGIN_KEY_ID = "editor_pruebas"
ADMIN_USER = "admin_prueba"
ADMIN_PASSWORD = "contraseña-de-prueba-1"


@pytest.fixture
def context(tmp_path: Path) -> RuntimeContext:
    return RuntimeContext(project_root=tmp_path)


@pytest.fixture
def kernel(context: RuntimeContext) -> Iterator[Kernel]:
    # Coste mínimo de contraseña: las pruebas no necesitan el coste de producción.
    instance = Kernel(context, password_iterations=1_000)
    instance.start()
    yield instance
    instance.stop()


def install_administrator(
    kernel: Kernel, username: str = ADMIN_USER, password: str = ADMIN_PASSWORD
) -> None:
    """Completa la instalación inicial con un código emitido en la propia prueba."""
    installer = kernel.security.installer
    installer.complete(installer.issue_code(), username, password)


@pytest.fixture
def admin(kernel: Kernel) -> tuple[str, str]:
    """Instala la plataforma con un administrador de pruebas y devuelve (usuario, contraseña)."""
    install_administrator(kernel)
    return ADMIN_USER, ADMIN_PASSWORD


@pytest.fixture
def make_manifest() -> Callable[..., Path]:
    """Crea versions/<version>/manifest.json con datos válidos salvo los indicados."""

    def _make(versions_dir: Path, folder_name: str, **overrides: Any) -> Path:
        data: dict[str, Any] = {
            "version": folder_name,
            "channel": "development",
            "compatible_kernel": "0.1.x",
            "name": f"Versión {folder_name}",
            "description": "Versión de prueba",
        }
        data.update(overrides)
        folder = versions_dir / folder_name
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / "manifest.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    return _make


@pytest.fixture
def make_module() -> Callable[..., Path]:
    """Crea modules/<id>/module.json con datos válidos salvo los indicados."""

    def _make(modules_dir: Path, module_id: str, **overrides: Any) -> Path:
        data: dict[str, Any] = {
            "id": module_id,
            "name": f"Módulo {module_id}",
            "version": "0.1.0",
            "description": "Módulo de prueba",
        }
        data.update(overrides)
        folder = modules_dir / module_id
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / "module.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    return _make


@pytest.fixture
def make_plugin_source() -> Callable[..., Path]:
    """Crea una carpeta de paquete de plugin firmada, con plugin.json y un archivo de datos."""

    def _make(
        root: Path,
        plugin_id: str = "plugin_ejemplo",
        version: str = "0.1.0",
        secret: bytes = PLUGIN_SECRET,
        key_id: str = PLUGIN_KEY_ID,
        **overrides: Any,
    ) -> Path:
        data: dict[str, Any] = {
            "id": plugin_id,
            "name": f"Plugin {plugin_id}",
            "version": version,
            "author": "Pruebas",
            "description": "Plugin de prueba",
            "api_version": "1.0",
            "compatible_kernel": "0.1.x",
        }
        data.update(overrides)
        root.mkdir(parents=True, exist_ok=True)
        (root / "plugin.json").write_text(json.dumps(data), encoding="utf-8")
        (root / "datos.txt").write_text("contenido de prueba", encoding="utf-8")
        build_package(root, secret, key_id)
        return root

    return _make


@pytest.fixture
def platform_token(kernel: Kernel) -> str:
    """Sesión reautenticada de la cuenta de la plataforma: autoriza operaciones de confianza.

    Instala la plataforma si todavía no tiene cuentas. Es la única vía de las pruebas para dar de
    alta editores o revocarlos: la misma que usa la aplicación.
    """
    if not kernel.security.has_accounts():
        install_administrator(kernel)
    token = kernel.security.login(ADMIN_USER, ADMIN_PASSWORD)
    kernel.security.reauthenticate(token, ADMIN_PASSWORD)
    return token


@pytest.fixture
def register_publisher(kernel: Kernel, platform_token: str) -> Callable[..., None]:
    """Registra un editor con la clave pública derivada de un secreto de prueba."""

    def _register(
        target: Kernel,
        trust_level: str = "official",
        key_id: str = PLUGIN_KEY_ID,
        secret: bytes = PLUGIN_SECRET,
    ) -> None:
        if target is not kernel:
            raise ValueError("el editor se registra en el núcleo de la prueba")
        target.plugins.register_publisher(
            platform_token,
            key_id=key_id,
            display_name=f"Editor {key_id}",
            public_key=ed25519.public_key(secret),
            trust_level=trust_level,
            confirmed=True,
        )

    return _register


# ----- Plataforma para pruebas HTTP -------------------------------------------------------


@pytest.fixture
def entorno(monkeypatch: pytest.MonkeyPatch) -> None:
    for nombre, valor in entorno_de_prueba().items():
        monkeypatch.setenv(nombre, valor)


@pytest.fixture
def arrancar(context: RuntimeContext, entorno: None) -> Iterator[Callable[..., Kernel]]:
    """Arranca la plataforma con configuración de prueba y la detiene al terminar la prueba."""
    kernels: list[Kernel] = []

    def _crear(**limites: Any) -> Kernel:
        escribir_configuracion(context.config_dir, limites={**LIMITES_PRUEBA, **limites})
        kernel = Kernel(context, password_iterations=1_000)
        kernel.start()
        install_administrator(kernel)
        kernels.append(kernel)
        return kernel

    yield _crear
    for kernel in kernels:
        kernel.stop()
