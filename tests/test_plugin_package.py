"""Paquetes de plugin: manifiesto, integridad, firma, editores, catálogo y revisión."""

import json
import os
from collections.abc import Callable
from pathlib import Path

import pytest

from natxajo_auditor.core import ed25519
from natxajo_auditor.core.exceptions import PluginError, StorageError, ValidationError
from natxajo_auditor.core.utilities import sha256_bytes
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.plugins.api import check_api_version
from natxajo_auditor.plugins.manifest import PluginManifest
from natxajo_auditor.plugins.package import (
    INTEGRITY_FILE,
    SIGNATURE_FILE,
    build_package,
    copy_package,
)
from natxajo_auditor.plugins.repository import LocalRepository
from natxajo_auditor.plugins.review import inventory, needs_manual_review
from natxajo_auditor.plugins.verifier import verify_package

OTHER_SECRET = bytes(range(100, 132))


def _manifest_data(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "id": "plugin_ejemplo",
        "name": "Ejemplo",
        "version": "0.1.0",
        "author": "Pruebas",
        "description": "Plugin de prueba",
        "api_version": "1.0",
        "compatible_kernel": "0.1.x",
    }
    data.update(overrides)
    return data


def test_manifest_accepts_valid_data() -> None:
    manifest = PluginManifest.from_mapping(
        _manifest_data(dependencies=["plugin_base"], permissions=["auditoria:nucleo:evento:leer"])
    )
    assert manifest.plugin_id == "plugin_ejemplo"
    assert manifest.dependencies == ("plugin_base",)
    assert manifest.permissions == ("auditoria:nucleo:evento:leer",)


@pytest.mark.parametrize(
    "overrides",
    [
        {"id": "X"},
        {"version": "1.0"},
        {"api_version": ""},
        {"compatible_kernel": "0.1"},
        {"dependencies": ["plugin_ejemplo"]},
        {"permissions": ["auditoria.leer"]},
        {"permissions": ["auditoria:*:*:leer"]},
        {"extra": "campo desconocido"},
    ],
)
def test_manifest_rejects_invalid_data(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        PluginManifest.from_mapping(_manifest_data(**overrides))


def test_manifest_rejects_missing_fields() -> None:
    data = _manifest_data()
    del data["author"]
    with pytest.raises(ValidationError, match="faltan campos"):
        PluginManifest.from_mapping(data)


def test_unsupported_api_version_is_rejected() -> None:
    with pytest.raises(ValidationError, match="versión de API no soportada"):
        check_api_version("9.0")


def test_valid_package_verifies(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    root = make_plugin_source(tmp_path / "pkg")
    verified = verify_package(root, kernel.plugins.trust, kernel.kernel_version)
    assert verified.manifest.plugin_id == "plugin_ejemplo"
    assert verified.publisher_key_id == "editor_pruebas"
    assert verified.trust_level == "official"
    assert len(verified.integrity_sha256) == 64


def test_modified_file_is_rejected(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    root = make_plugin_source(tmp_path / "pkg")
    (root / "datos.txt").write_text("alterado", encoding="utf-8")
    with pytest.raises(ValidationError, match="archivos alterados: datos.txt"):
        verify_package(root, kernel.plugins.trust, kernel.kernel_version)


def test_altered_manifest_is_rejected(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    root = make_plugin_source(tmp_path / "pkg")
    data = json.loads((root / "plugin.json").read_text(encoding="utf-8"))
    data["description"] = "cambiado"
    (root / "plugin.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValidationError, match="archivos alterados: plugin.json"):
        verify_package(root, kernel.plugins.trust, kernel.kernel_version)


def test_added_file_is_rejected(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    root = make_plugin_source(tmp_path / "pkg")
    (root / "extra.txt").write_text("añadido", encoding="utf-8")
    with pytest.raises(ValidationError, match="archivos no declarados: extra.txt"):
        verify_package(root, kernel.plugins.trust, kernel.kernel_version)


def test_removed_file_is_rejected(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    root = make_plugin_source(tmp_path / "pkg")
    (root / "datos.txt").unlink()
    with pytest.raises(ValidationError, match="faltan archivos: datos.txt"):
        verify_package(root, kernel.plugins.trust, kernel.kernel_version)


def test_forged_integrity_file_breaks_signature(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    root = make_plugin_source(tmp_path / "pkg")
    document = json.loads((root / INTEGRITY_FILE).read_text(encoding="utf-8"))
    document["files"]["datos.txt"] = "0" * 64
    (root / INTEGRITY_FILE).write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValidationError, match="la firma no corresponde"):
        verify_package(root, kernel.plugins.trust, kernel.kernel_version)


def test_signature_from_another_key_is_rejected(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    root = make_plugin_source(tmp_path / "pkg", secret=OTHER_SECRET)
    with pytest.raises(ValidationError, match="la firma no corresponde"):
        verify_package(root, kernel.plugins.trust, kernel.kernel_version)


def test_unknown_publisher_is_rejected(
    kernel: Kernel, tmp_path: Path, make_plugin_source: Callable[..., Path]
) -> None:
    root = make_plugin_source(tmp_path / "pkg")
    with pytest.raises(ValidationError, match="editor no registrado"):
        verify_package(root, kernel.plugins.trust, kernel.kernel_version)


def test_revoked_publisher_is_rejected(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
    platform_token: str,
) -> None:
    register_publisher(kernel)
    kernel.plugins.revoke_publisher(platform_token, "editor_pruebas", confirmed=True)
    root = make_plugin_source(tmp_path / "pkg")
    with pytest.raises(ValidationError, match="revocado"):
        verify_package(root, kernel.plugins.trust, kernel.kernel_version)


def test_package_without_signature_is_rejected(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    root = make_plugin_source(tmp_path / "pkg")
    (root / SIGNATURE_FILE).unlink()
    with pytest.raises(ValidationError, match="no contiene signature.json"):
        verify_package(root, kernel.plugins.trust, kernel.kernel_version)


def test_only_ed25519_signatures_are_accepted(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    root = make_plugin_source(tmp_path / "pkg")
    document = json.loads((root / SIGNATURE_FILE).read_text(encoding="utf-8"))
    document["algorithm"] = "rsa"
    (root / SIGNATURE_FILE).write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValidationError, match="algoritmo de firma no soportado"):
        verify_package(root, kernel.plugins.trust, kernel.kernel_version)


def test_incompatible_kernel_is_rejected(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    root = make_plugin_source(tmp_path / "pkg", compatible_kernel="0.2.x")
    with pytest.raises(ValidationError, match="requiere núcleo 0.2.x"):
        verify_package(root, kernel.plugins.trust, kernel.kernel_version)


@pytest.mark.skipif(os.name == "nt", reason="los enlaces simbólicos requieren permisos en Windows")
def test_symlinks_are_rejected(tmp_path: Path, make_plugin_source: Callable[..., Path]) -> None:
    root = make_plugin_source(tmp_path / "pkg")
    (root / "enlace.txt").symlink_to(root / "datos.txt")
    with pytest.raises(ValidationError, match="enlaces simbólicos no permitidos"):
        build_package(root, bytes(range(1, 33)), "editor_pruebas")


def test_copied_package_keeps_its_integrity(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    source = make_plugin_source(tmp_path / "pkg")
    copy = tmp_path / "copia"
    copy_package(source, copy)
    original = verify_package(source, kernel.plugins.trust, kernel.kernel_version)
    duplicate = verify_package(copy, kernel.plugins.trust, kernel.kernel_version)
    assert original.integrity_sha256 == duplicate.integrity_sha256
    assert sha256_bytes((copy / "datos.txt").read_bytes()) == sha256_bytes(
        (source / "datos.txt").read_bytes()
    )


def _publish(kernel: Kernel, token: str, key_id: str, public: bytes, trust_level: str) -> None:
    kernel.plugins.register_publisher(
        token,
        key_id=key_id,
        display_name="Editor",
        public_key=public,
        trust_level=trust_level,
        confirmed=True,
    )


def test_trust_store_registers_and_revokes(kernel: Kernel, platform_token: str) -> None:
    public = ed25519.public_key(bytes(range(1, 33)))
    _publish(kernel, platform_token, "editor_uno", public, "verified")
    publisher = kernel.plugins.trust.get_publisher("editor_uno")
    assert publisher.public_key == public
    assert publisher.trust_level == "verified"
    kernel.plugins.revoke_publisher(platform_token, "editor_uno", confirmed=True)
    assert kernel.plugins.trust.get_publisher("editor_uno").trust_level == "revoked"
    assert [item.key_id for item in kernel.plugins.trust.publishers()] == ["editor_uno"]


def test_trust_store_rejects_bad_input(kernel: Kernel, platform_token: str) -> None:
    public = ed25519.public_key(bytes(range(1, 33)))
    with pytest.raises(ValidationError):
        _publish(kernel, platform_token, "Mal Id!", public, "verified")
    with pytest.raises(ValidationError, match="32 bytes"):
        _publish(kernel, platform_token, "editor_dos", b"corta", "verified")
    with pytest.raises(ValidationError, match="nivel de confianza"):
        _publish(kernel, platform_token, "editor_tres", public, "oro")
    _publish(kernel, platform_token, "editor_cuatro", public, "verified")
    with pytest.raises(PluginError, match="ya está registrado"):
        _publish(kernel, platform_token, "editor_cuatro", public, "verified")
    with pytest.raises(PluginError, match="no registrado"):
        kernel.plugins.trust.get_publisher("nadie")


def _build_catalog(
    repo_root: Path,
    make_plugin_source: Callable[..., Path],
    *,
    digest: str | None = None,
    path: str = "plugins/plugin_ejemplo/0.1.0",
    version: str = "0.1.0",
) -> None:
    folder = repo_root / "plugins" / "plugin_ejemplo" / "0.1.0"
    make_plugin_source(folder)
    actual = sha256_bytes((folder / INTEGRITY_FILE).read_bytes())
    index = {
        "format": 1,
        "plugins": [
            {
                "id": "plugin_ejemplo",
                "version": version,
                "path": path,
                "sha256": digest or actual,
            }
        ],
    }
    (repo_root / "index.json").write_text(json.dumps(index), encoding="utf-8")


def test_repository_fetch_verifies_index_and_package(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel)
    repo_root = tmp_path / "repo"
    _build_catalog(repo_root, make_plugin_source)
    repository = LocalRepository(repo_root)
    entry = repository.find("plugin_ejemplo", "0.1.0")
    staging = tmp_path / "staging"
    staging.mkdir()
    fetched = repository.fetch(entry, staging)
    verified = verify_package(fetched, kernel.plugins.trust, kernel.kernel_version)
    assert verified.manifest.version == "0.1.0"


def test_repository_rejects_index_that_does_not_match_package(
    tmp_path: Path, make_plugin_source: Callable[..., Path]
) -> None:
    repo_root = tmp_path / "repo"
    _build_catalog(repo_root, make_plugin_source, digest="0" * 64)
    repository = LocalRepository(repo_root)
    entry = repository.find("plugin_ejemplo", "0.1.0")
    staging = tmp_path / "staging"
    staging.mkdir()
    with pytest.raises(ValidationError, match="no coincide"):
        repository.fetch(entry, staging)


def test_repository_rejects_paths_outside_the_repository(
    tmp_path: Path, make_plugin_source: Callable[..., Path]
) -> None:
    repo_root = tmp_path / "repo"
    _build_catalog(repo_root, make_plugin_source, path="../fuera")
    with pytest.raises(ValidationError, match="fuera del repositorio"):
        LocalRepository(repo_root).entries()


def test_repository_reports_missing_entries(
    tmp_path: Path, make_plugin_source: Callable[..., Path]
) -> None:
    repo_root = tmp_path / "repo"
    _build_catalog(repo_root, make_plugin_source)
    with pytest.raises(PluginError, match="no tiene otro_plugin 0.1.0"):
        LocalRepository(repo_root).find("otro_plugin", "0.1.0")


def test_inventory_flags_executable_content(
    tmp_path: Path, make_plugin_source: Callable[..., Path]
) -> None:
    root = make_plugin_source(tmp_path / "pkg")
    (root / "ayuda.ps1").write_text("Write-Output 'hola'", encoding="utf-8")
    items = inventory(root)
    assert [item.path for item in items] == ["ayuda.ps1", "datos.txt", "plugin.json"]
    assert [item.kind for item in items] == ["ejecutable", "datos", "datos"]
    assert needs_manual_review(items)


SHA = "a" * 64
OTRO_SHA = "b" * 64
EDITOR = "editor-ejemplo"


def test_review_log_keeps_history_and_latest_decision(kernel: Kernel) -> None:
    reviews = kernel.plugins.reviews
    reviews.record("plugin_ejemplo", "0.1.0", EDITOR, SHA, "Ana", "rejected", "falta documentación")
    assert not reviews.is_approved("plugin_ejemplo", "0.1.0", EDITOR, SHA)
    reviews.record("plugin_ejemplo", "0.1.0", EDITOR, SHA, "Ana", "approved", "correcto")
    assert reviews.is_approved("plugin_ejemplo", "0.1.0", EDITOR, SHA)
    assert reviews.latest_decision("plugin_ejemplo", "0.1.0", EDITOR, SHA) == "approved"
    assert [item["decision"] for item in reviews.history("plugin_ejemplo", "0.1.0")] == [
        "rejected",
        "approved",
    ]


def test_an_approval_does_not_carry_over_to_other_content_publisher_or_version(
    kernel: Kernel,
) -> None:
    reviews = kernel.plugins.reviews
    reviews.record("plugin_ejemplo", "0.1.0", EDITOR, SHA, "Ana", "approved", "correcto")
    assert reviews.is_approved("plugin_ejemplo", "0.1.0", EDITOR, SHA)
    assert not reviews.is_approved("plugin_ejemplo", "0.1.0", EDITOR, OTRO_SHA)
    assert not reviews.is_approved("plugin_ejemplo", "0.1.0", "editor-otro", SHA)
    assert not reviews.is_approved("plugin_ejemplo", "0.2.0", EDITOR, SHA)


def test_review_log_rejects_invalid_input(kernel: Kernel) -> None:
    reviews = kernel.plugins.reviews
    with pytest.raises(ValidationError, match="decisión de revisión no válida"):
        reviews.record("plugin_ejemplo", "0.1.0", EDITOR, SHA, "Ana", "tal vez", "")
    with pytest.raises(ValidationError):
        reviews.record("plugin_ejemplo", "0.1.0", EDITOR, SHA, "  ", "approved", "")
    with pytest.raises(ValidationError, match="SHA-256"):
        reviews.record("plugin_ejemplo", "0.1.0", EDITOR, "no-es-un-hash", "Ana", "approved", "")


def test_review_rows_cannot_be_changed_or_removed(kernel: Kernel) -> None:
    reviews = kernel.plugins.reviews
    reviews.record("plugin_ejemplo", "0.1.0", EDITOR, SHA, "Ana", "approved", "correcto")
    with pytest.raises(StorageError, match="no se modifica"):
        reviews._database.execute("UPDATE plugin_reviews SET decision = 'rejected'")
    with pytest.raises(StorageError, match="no se elimina"):
        reviews._database.execute("DELETE FROM plugin_reviews")
    assert reviews.is_approved("plugin_ejemplo", "0.1.0", EDITOR, SHA)
