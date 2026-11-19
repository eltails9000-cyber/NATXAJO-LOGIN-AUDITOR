"""Punto de entrada: `python main.py`. Funciona sin instalar el paquete."""

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
_SRC = _PROJECT_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from natxajo_auditor.main import main

if __name__ == "__main__":
    raise SystemExit(main(project_root=_PROJECT_ROOT))
