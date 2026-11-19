import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel


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
