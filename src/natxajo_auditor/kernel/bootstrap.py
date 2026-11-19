import os
from pathlib import Path

from natxajo_auditor.kernel.context import RuntimeContext


def create_context(project_root: Path | None = None) -> RuntimeContext:
    root = project_root or Path.cwd()
    return RuntimeContext(
        environment=os.getenv("APP_ENV", "development"),
        locale=os.getenv("APP_LOCALE", "es"),
        project_root=root,
        data_dir=root / os.getenv("DATA_DIR", "data"),
        config_dir=root / os.getenv("CONFIG_DIR", "config"),
        log_dir=root / os.getenv("LOG_DIR", "logs"),
        report_dir=root / os.getenv("REPORT_DIR", "reports"),
        storage_dir=root / os.getenv("STORAGE_DIR", "storage"),
    )
