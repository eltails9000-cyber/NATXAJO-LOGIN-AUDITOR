from pathlib import Path


def test_kernel_starts_and_stops(tmp_path: Path) -> None:
    from natxajo_auditor.kernel.context import RuntimeContext
    from natxajo_auditor.kernel.kernel import Kernel

    context = RuntimeContext(
        project_root=tmp_path,
        data_dir=tmp_path / "data",
        config_dir=tmp_path / "config",
        log_dir=tmp_path / "logs",
        report_dir=tmp_path / "reports",
        storage_dir=tmp_path / "storage",
    )
    kernel = Kernel(context)
    kernel.startup()
    assert kernel.health()["status"] == "healthy"
    kernel.shutdown()
    assert kernel.health()["state"] == "stopped"


def test_configuration_persistence(tmp_path: Path) -> None:
    from natxajo_auditor.configuration.configuration_manager import ConfigurationManager

    path = tmp_path / "app.json"
    manager = ConfigurationManager(path)
    manager.set("general", "theme", "light")
    reloaded = ConfigurationManager(path)
    assert reloaded.get("general", "theme") == "light"


def test_manual_version_loading(tmp_path: Path) -> None:
    from natxajo_auditor.kernel.context import RuntimeContext
    from natxajo_auditor.kernel.kernel import Kernel

    context = RuntimeContext(storage_dir=tmp_path)
    kernel = Kernel(context)
    kernel.startup()
    manager = kernel.container.get("versions")
    assert manager.load("0.1.0") == "0.1.0"
    kernel.shutdown()
