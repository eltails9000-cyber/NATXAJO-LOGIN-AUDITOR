import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


class StorageManager:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.backups = root / "backups"
        self.root.mkdir(parents=True, exist_ok=True)
        self.backups.mkdir(parents=True, exist_ok=True)

    def backup_file(self, source: Path, label: str = "manual") -> Path:
        if not source.is_file():
            raise FileNotFoundError(str(source))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = self.backups / f"{stamp}-{label}-{source.name}"
        shutil.copy2(source, target)
        manifest = target.with_suffix(target.suffix + ".manifest.json")
        manifest.write_text(json.dumps({"source": str(source), "backup": target.name}, indent=2), encoding="utf-8")
        return target

    def restore_file(self, backup: Path, target: Path, authorized: bool = False) -> None:
        if not authorized:
            raise PermissionError("La restauración requiere autorización explícita")
        if target.exists():
            raise FileExistsError("El destino existe; confirme explícitamente una sustitución autorizada")
        if not backup.is_file():
            raise FileNotFoundError(str(backup))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup, target)

    def integrity(self) -> dict[str, object]:
        missing = [str(path) for path in self.root.rglob("*") if not path.exists()]
        return {"status": "healthy" if not missing else "degraded", "missing": missing}
