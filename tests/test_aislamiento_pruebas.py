"""Las pruebas trabajan solo en carpetas temporales y nunca dentro del repositorio ni de datos reales."""

from __future__ import annotations

from pathlib import Path

from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel

REPOSITORY = Path(__file__).resolve().parents[1]


def test_the_context_fixture_points_at_the_temporary_folder(
    context: RuntimeContext, tmp_path: Path
) -> None:
    assert context.project_root.resolve() == tmp_path.resolve()
    assert REPOSITORY not in (
        context.project_root.resolve(),
        *context.project_root.resolve().parents,
    )


def test_a_kernel_writes_only_under_its_temporary_project_root(
    kernel: Kernel, tmp_path: Path
) -> None:
    root = tmp_path.resolve()
    for folder in (kernel.context.config_dir, kernel.context.storage_dir):
        assert root in folder.resolve().parents
    assert REPOSITORY not in root.parents
