from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RuntimeContext:
    environment: str = "development"
    locale: str = "es"
    project_root: Path = field(default_factory=Path.cwd)
    data_dir: Path = field(default_factory=lambda: Path.cwd() / "data")
    config_dir: Path = field(default_factory=lambda: Path.cwd() / "config")
    log_dir: Path = field(default_factory=lambda: Path.cwd() / "logs")
    report_dir: Path = field(default_factory=lambda: Path.cwd() / "reports")
    storage_dir: Path = field(default_factory=lambda: Path.cwd() / "storage")
