import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from natxajo_auditor.core.exceptions import ValidationError

MANIFEST_SUFFIX = ".manifest.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
        manifest = self._manifest_path(target)
        manifest.write_text(
            json.dumps(
                {"source": str(source), "backup": target.name, "sha256": _sha256(target)},
                indent=2,
            ),
            encoding="utf-8",
        )
        return target

    def restore_file(self, backup: Path, target: Path, authorized: bool = False) -> None:
        if not authorized:
            raise PermissionError("La restauración requiere autorización explícita")
        if target.exists():
            raise FileExistsError(
                "El destino existe; confirme explícitamente una sustitución autorizada"
            )
        if not backup.is_file():
            raise FileNotFoundError(str(backup))
        problem = self._verify(backup)
        if problem:
            raise ValidationError(f"La copia no se puede restaurar: {problem}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup, target)

    def integrity(self) -> dict[str, object]:
        """Verifica cada copia y su manifiesto.

        Detecta copias ausentes, manifiestos ausentes o ilegibles, y copias
        cuyo SHA-256 ya no coincide con el registrado al crearlas.
        """
        names: set[str] = set()
        for entry in self.backups.iterdir():
            if not entry.is_file():
                continue
            if entry.name.endswith(MANIFEST_SUFFIX):
                names.add(entry.name[: -len(MANIFEST_SUFFIX)])
            else:
                names.add(entry.name)
        problems: list[str] = []
        for name in sorted(names):
            problem = self._verify(self.backups / name)
            if problem:
                problems.append(f"{name}: {problem}")
        return {"status": "healthy" if not problems else "degraded", "problems": problems}

    @staticmethod
    def _manifest_path(backup: Path) -> Path:
        return backup.with_name(backup.name + MANIFEST_SUFFIX)

    def _verify(self, backup: Path) -> str | None:
        if not backup.is_file():
            return "falta la copia"
        manifest = self._manifest_path(backup)
        if not manifest.is_file():
            return "falta el manifiesto"
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return f"manifiesto ilegible: {exc}"
        expected = data.get("sha256") if isinstance(data, dict) else None
        if not isinstance(expected, str):
            return "el manifiesto no contiene sha256"
        if _sha256(backup) != expected:
            return "el hash no coincide: la copia fue alterada"
        return None
