import sys
from pathlib import Path

# Permite ejecutar `python main.py` sin instalar el paquete (layout src/).
_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from natxajo_auditor.main import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
