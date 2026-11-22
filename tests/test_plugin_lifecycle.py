"""Ciclo de vida de plugins: instalar, habilitar, deshabilitar, revocar y desinstalar."""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from natxajo_auditor.core.exceptions import PluginError, ValidationError
from natxajo_auditor.core.utilities import sha256_bytes
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.plugins.package import INTEGRITY_FILE
from natxajo_auditor.plugins.repository import LocalRepository

BASE_SECRET = bytes(range(40, 72))
APP_SECRET = bytes(range(70, 102))


def _store_dir(kernel: Kernel, plugin_id: str, version: str) -> Path:
    return kernel.context.plugins_dir / "store" / plugin_id / version


def test_kernel_exposes_the_plugin_service(kernel: Kernel) -> None:
    assert "plugins" in kernel.services.names()


def test_install_stores_a_disabled_plugin(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    source = make_plugin_source(tmp_path / "pkg")
    record = kernel.plugins.install_package(source)
    assert record.plugin_id == "plugin_ejemplo"
    assert record.enabled is False
    assert record.trust_level == "official"
    assert (_store_dir(kernel, "plugin_ejemplo", "0.1.0") / "plugin.json").is_file()
    assert [item.plugin_id for item in kernel.plugins.list_plugins()] == ["plugin_ejemplo"]
    installed = kernel.audit.events_of_type("plugin.installed")
    assert installed[0]["payload"]["plugin"] == "plugin_ejemplo"
    assert not any((kernel.context.plugins_dir / "work").iterdir())


def test_rejected_package_is_audited_and_not_stored(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
    platform_token: str,
) -> None:
    register_publisher(kernel)
    kernel.plugins.revoke_publisher(platform_token, "editor_pruebas", confirmed=True)
    source = make_plugin_source(tmp_path / "pkg")
    with pytest.raises(ValidationError, match="revocado"):
        kernel.plugins.install_package(source)
    assert kernel.plugins.list_plugins() == []
    assert not _store_dir(kernel, "plugin_ejemplo", "0.1.0").exists()
    rejected = kernel.audit.events_of_type("plugin.rejected")
    assert len(rejected) == 1
    assert "revocado" in rejected[0]["payload"]["reason"]


def test_second_version_of_an_installed_plugin_is_refused(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    kernel.plugins.install_package(make_plugin_source(tmp_path / "v1"))
    with pytest.raises(PluginError, match="ya hay una versión instalada"):
        kernel.plugins.install_package(make_plugin_source(tmp_path / "v2", version="0.2.0"))


def test_enable_and_disable_are_idempotent(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    kernel.plugins.install_package(make_plugin_source(tmp_path / "pkg"))
    assert kernel.plugins.enable("plugin_ejemplo") == ["plugin_ejemplo"]
    assert kernel.plugins.enable("plugin_ejemplo") == []
    assert kernel.plugins.get("plugin_ejemplo").enabled is True
    kernel.plugins.disable("plugin_ejemplo")
    kernel.plugins.disable("plugin_ejemplo")
    assert kernel.plugins.get("plugin_ejemplo").enabled is False
    assert len(kernel.audit.events_of_type("plugin.enabled")) == 1
    assert len(kernel.audit.events_of_type("plugin.disabled")) == 1


def test_enable_loads_dependencies_first_and_protects_them(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    kernel.plugins.install_package(make_plugin_source(tmp_path / "base", plugin_id="plugin_base"))
    kernel.plugins.install_package(
        make_plugin_source(tmp_path / "app", plugin_id="plugin_app", dependencies=["plugin_base"])
    )
    assert kernel.plugins.enable("plugin_app") == ["plugin_base", "plugin_app"]
    with pytest.raises(PluginError, match="lo requieren plugin_app"):
        kernel.plugins.disable("plugin_base")
    kernel.plugins.disable("plugin_app")
    kernel.plugins.disable("plugin_base")


def test_enable_with_missing_dependency_names_the_requester(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    kernel.plugins.install_package(
        make_plugin_source(tmp_path / "app", plugin_id="plugin_app", dependencies=["plugin_falta"])
    )
    with pytest.raises(PluginError, match="plugin no instalado: plugin_falta"):
        kernel.plugins.enable("plugin_app")
    assert kernel.plugins.get("plugin_app").enabled is False


def test_third_party_plugin_needs_an_approved_review(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
    platform_token: str,
) -> None:
    register_publisher(kernel, trust_level="third_party")
    kernel.plugins.install_package(make_plugin_source(tmp_path / "pkg"))
    with pytest.raises(PluginError, match="requiere una revisión aprobada"):
        kernel.plugins.enable("plugin_ejemplo")
    kernel.plugins.record_review(
        platform_token, "plugin_ejemplo", "rejected", "pendiente", confirmed=True
    )
    with pytest.raises(PluginError, match="requiere una revisión aprobada"):
        kernel.plugins.enable("plugin_ejemplo")
    kernel.plugins.record_review(
        platform_token, "plugin_ejemplo", "approved", "correcto", confirmed=True
    )
    assert kernel.plugins.enable("plugin_ejemplo") == ["plugin_ejemplo"]
    assert kernel.plugins.get("plugin_ejemplo").approved_review is True


def test_altered_stored_copy_blocks_enabling(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    kernel.plugins.install_package(make_plugin_source(tmp_path / "pkg"))
    (_store_dir(kernel, "plugin_ejemplo", "0.1.0") / "datos.txt").write_text(
        "alterado", encoding="utf-8"
    )
    with pytest.raises(PluginError, match="no es válida"):
        kernel.plugins.enable("plugin_ejemplo")


def test_revoking_a_publisher_disables_its_plugins_and_dependents(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
    platform_token: str,
) -> None:
    register_publisher(kernel, key_id="editor_base", secret=BASE_SECRET)
    register_publisher(kernel, key_id="editor_app", secret=APP_SECRET)
    kernel.plugins.install_package(
        make_plugin_source(
            tmp_path / "base",
            plugin_id="plugin_base",
            secret=BASE_SECRET,
            key_id="editor_base",
        )
    )
    kernel.plugins.install_package(
        make_plugin_source(
            tmp_path / "app",
            plugin_id="plugin_app",
            secret=APP_SECRET,
            key_id="editor_app",
            dependencies=["plugin_base"],
        )
    )
    kernel.plugins.install_package(
        make_plugin_source(
            tmp_path / "otro",
            plugin_id="plugin_otro",
            secret=APP_SECRET,
            key_id="editor_app",
        )
    )
    kernel.plugins.enable("plugin_app")
    kernel.plugins.enable("plugin_otro")

    disabled = kernel.plugins.revoke_publisher(platform_token, "editor_base", confirmed=True)

    assert disabled == ["plugin_app", "plugin_base"]
    states = {item.plugin_id: item.enabled for item in kernel.plugins.list_plugins()}
    assert states == {"plugin_app": False, "plugin_base": False, "plugin_otro": True}
    assert len(kernel.audit.events_of_type("plugin.publisher_revoked")) == 1
    with pytest.raises(PluginError, match="revocado"):
        kernel.plugins.enable("plugin_base")


def test_uninstall_follows_the_dependency_rules(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    kernel.plugins.install_package(make_plugin_source(tmp_path / "base", plugin_id="plugin_base"))
    kernel.plugins.install_package(
        make_plugin_source(tmp_path / "app", plugin_id="plugin_app", dependencies=["plugin_base"])
    )
    kernel.plugins.enable("plugin_app")
    with pytest.raises(PluginError, match="deshabilite plugin_app"):
        kernel.plugins.uninstall("plugin_app")
    kernel.plugins.disable("plugin_app")
    kernel.plugins.disable("plugin_base")
    with pytest.raises(PluginError, match="lo requieren plugin_app"):
        kernel.plugins.uninstall("plugin_base")

    kernel.plugins.uninstall("plugin_app")
    kernel.plugins.uninstall("plugin_base")

    assert kernel.plugins.list_plugins() == []
    assert not _store_dir(kernel, "plugin_base", "0.1.0").exists()
    assert len(kernel.audit.events_of_type("plugin.uninstalled")) == 2


def test_inspect_verifies_without_installing(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    source = make_plugin_source(tmp_path / "pkg")
    verified, items = kernel.plugins.inspect_package(source)
    assert verified.manifest.plugin_id == "plugin_ejemplo"
    assert [item.path for item in items] == ["datos.txt", "plugin.json"]
    assert kernel.plugins.list_plugins() == []


def test_install_from_repository_checks_the_catalog_entry(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    repo_root = tmp_path / "repo"
    folder = repo_root / "plugins" / "plugin_ejemplo" / "0.1.0"
    make_plugin_source(folder)
    digest = sha256_bytes((folder / INTEGRITY_FILE).read_bytes())
    entry = {
        "id": "plugin_ejemplo",
        "version": "0.1.0",
        "path": "plugins/plugin_ejemplo/0.1.0",
        "sha256": digest,
    }
    (repo_root / "index.json").write_text(
        json.dumps({"format": 1, "plugins": [entry]}), encoding="utf-8"
    )
    repository = LocalRepository(repo_root)

    record = kernel.plugins.install_from_repository(repository, "plugin_ejemplo", "0.1.0")
    assert record.version == "0.1.0"

    lying = dict(entry, version="0.2.0")
    (repo_root / "index.json").write_text(
        json.dumps({"format": 1, "plugins": [lying]}), encoding="utf-8"
    )
    with pytest.raises(ValidationError, match="no corresponde a la entrada del catálogo"):
        kernel.plugins.install_from_repository(repository, "plugin_ejemplo", "0.2.0")


def test_review_requires_an_installed_plugin(kernel: Kernel, platform_token: str) -> None:
    with pytest.raises(PluginError, match="plugin no instalado"):
        kernel.plugins.record_review(
            platform_token, "plugin_ejemplo", "approved", "", confirmed=True
        )


def test_state_survives_a_restart(
    kernel: Kernel,
    context: RuntimeContext,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    kernel.plugins.install_package(make_plugin_source(tmp_path / "pkg"))
    kernel.plugins.enable("plugin_ejemplo")
    kernel.stop()

    restarted = Kernel(context)
    restarted.start()
    try:
        record = restarted.plugins.get("plugin_ejemplo")
        assert record.enabled is True
        assert record.trust_level == "official"
    finally:
        restarted.stop()
