import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_root_entry_point_runs_without_installing_package(tmp_path: Path) -> None:
    # Ejecuta main.py desde un directorio vacío y sin instalar el paquete.
    result = subprocess.run(
        [sys.executable, str(ROOT / "main.py")],
        input="0\n",
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "NATXAJO-LOGIN-AUDITOR" in result.stdout
