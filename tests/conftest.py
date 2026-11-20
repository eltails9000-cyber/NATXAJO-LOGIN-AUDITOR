import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from natxajo_auditor.core import ed25519
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.plugins.package import build_package

PLUGIN_SECRET = bytes(range(1, 33))
PLUGIN_KEY_ID = "editor_pruebas"


@pytest.fixture
def context(tmp_path: Path) -> RuntimeContext:
    return RuntimeContext(project_root=tmp_path)


@pytest.fixture
def kernel(context: RuntimeContext) -> Iterator[Kernel]:
    instance = Kernel(context)
    instance.start()
    yield instance
    instance.stop()


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
def register_publisher() -> Callable[..., None]:
    """Registra un editor con la clave pública derivada de un secreto de prueba."""

    def _register(
        kernel: Kernel,
        trust_level: str = "official",
        key_id: str = PLUGIN_KEY_ID,
        secret: bytes = PLUGIN_SECRET,
    ) -> None:
        kernel.plugins.trust.add_publisher(
            key_id, f"Editor {key_id}", ed25519.public_key(secret), trust_level
        )

    return _register
