"""Cuarentena, actualización y reversión de plugins (etapa 4, fase 6).

Cada cambio pasa por la puerta de operaciones. Estas pruebas cubren quién puede hacerlo, qué exige
(permiso, confirmación, reautenticación), qué queda auditado, qué ocurre si una copia del almacén
se altera y qué reglas aplica la base de datos.
"""

import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

from natxajo_auditor.core.contracts import (
    PLUGIN_QUARANTINE_PERMISSION,
    PLUGIN_QUARANTINE_RELEASE_PERMISSION,
    PLUGIN_VERSION_PERMISSION,
)
from natxajo_auditor.core.exceptions import (
    AuthorizationError,
    PluginError,
    SessionError,
    StorageError,
    ValidationError,
)
from natxajo_auditor.kernel.kernel import SERVICE_DATABASE, Kernel
from natxajo_auditor.security.guard import CRITICAL_PERMISSIONS
from natxajo_auditor.storage.database import Database
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, PLUGIN_KEY_ID

PASSWORD = "contraseña-de-prueba-3"
PLUGIN = "plugin_ejemplo"
DEPENDENT = "plugin_dependiente"
OTHER_KEY = "editor_otro"
OTHER_SECRET = bytes(range(40, 72))
OPERATOR = "operador_plugins"
AUDITOR = "auditor_plugins"


def _session(kernel: Kernel, username: str, password: str, *, reauthenticate: bool) -> str:
    token = kernel.security.login(username, password)
    if reauthenticate:
        kernel.security.reauthenticate(token, password)
    return token


def _database(kernel: Kernel) -> Database:
    return cast(Database, kernel.services.get(SERVICE_DATABASE))


def _stored(kernel: Kernel, plugin_id: str, version: str) -> Path:
    return kernel.plugins._store.path_for(plugin_id, version)


@pytest.fixture
def make_package(tmp_path: Path, make_plugin_source: Callable[..., Path]) -> Callable[..., Path]:
    """Paquete firmado en una carpeta propia. Por omisión, plugin_ejemplo 0.1.0 del editor de prueba."""

    def _make(name: str, version: str = "0.1.0", **overrides: Any) -> Path:
        return make_plugin_source(tmp_path / name, version=version, **overrides)

    return _make


@pytest.fixture
def accounts(kernel: Kernel, platform_token: str) -> None:
    kernel.security.create_account(OPERATOR, PASSWORD, ["operador"])
    kernel.security.create_account(AUDITOR, PASSWORD, ["auditor"])


@pytest.fixture
def installed(
    kernel: Kernel,
    platform_token: str,
    accounts: None,
    register_publisher: Callable[..., None],
    make_package: Callable[..., Path],
) -> Kernel:
    """Plataforma con un editor oficial y plugin_ejemplo 0.1.0 instalado y deshabilitado."""
    register_publisher(kernel, trust_level="official")
    kernel.plugins.install_package(make_package("base"))
    return kernel


# Positivas: cuarentena


def test_quarantine_blocks_enabling_and_names_the_account(
    installed: Kernel, platform_token: str
) -> None:
    installed.plugins.quarantine(platform_token, PLUGIN, "fallo de validación de sesiones")
    assert installed.plugins.get(PLUGIN).quarantined
    with pytest.raises(PluginError, match="en cuarentena"):
        installed.plugins.enable(PLUGIN)
    event = installed.audit.events_of_type("plugin.quarantined")[-1]
    assert event["payload"] == {
        "plugin": PLUGIN,
        "version": "0.1.0",
        "reason": "fallo de validación de sesiones",
        "username": ADMIN_USER,
    }
    assert event["category"] == "seguridad"


def test_quarantine_disables_enabled_dependents_and_says_why(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    installed.plugins.install_package(
        make_package("dependiente", plugin_id=DEPENDENT, dependencies=[PLUGIN])
    )
    installed.plugins.enable(DEPENDENT)
    assert installed.plugins.enabled_ids() == {PLUGIN, DEPENDENT}

    disabled = installed.plugins.quarantine(platform_token, PLUGIN, "motivo de prueba")

    assert disabled == [DEPENDENT, PLUGIN]
    assert installed.plugins.enabled_ids() == set()
    reasons = [
        event["payload"]["reason"]
        for event in installed.audit.events_of_type("plugin.disabled")[-2:]
    ]
    assert reasons == [f"en cuarentena: {PLUGIN}", f"en cuarentena: {PLUGIN}"]


def test_releasing_needs_confirmation_and_recent_reauthentication(
    installed: Kernel, platform_token: str
) -> None:
    installed.plugins.quarantine(platform_token, PLUGIN, "motivo")
    with pytest.raises(AuthorizationError, match="confirmación"):
        installed.plugins.release_quarantine(platform_token, PLUGIN)
    stale = _session(installed, ADMIN_USER, ADMIN_PASSWORD, reauthenticate=False)
    with pytest.raises(AuthorizationError, match="reautentique"):
        installed.plugins.release_quarantine(stale, PLUGIN, confirmed=True)
    assert installed.plugins.get(PLUGIN).quarantined

    installed.plugins.release_quarantine(platform_token, PLUGIN, confirmed=True)

    assert not installed.plugins.get(PLUGIN).quarantined
    installed.plugins.enable(PLUGIN)
    released = installed.audit.events_of_type("plugin.quarantine_released")[-1]
    assert released["payload"] == {"plugin": PLUGIN, "version": "0.1.0", "username": ADMIN_USER}


def test_uninstalling_a_quarantined_plugin_removes_its_quarantine(
    installed: Kernel, platform_token: str
) -> None:
    installed.plugins.quarantine(platform_token, PLUGIN, "motivo")
    installed.plugins.uninstall(PLUGIN)
    assert installed.plugins.list_plugins() == []
    assert _database(installed).fetchall("SELECT COUNT(*) FROM plugin_quarantine") == [(0,)]


# Positivas: actualización y reversión


def test_update_installs_a_newer_version_and_keeps_the_previous_copy(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    record = installed.plugins.update_package(
        platform_token, make_package("v2", "0.2.0"), confirmed=True
    )
    assert (record.version, record.previous_version, record.enabled) == ("0.2.0", "0.1.0", False)
    assert _stored(installed, PLUGIN, "0.1.0").is_dir()
    assert _stored(installed, PLUGIN, "0.2.0").is_dir()
    event = installed.audit.events_of_type("plugin.updated")[-1]
    assert event["payload"] == {
        "plugin": PLUGIN,
        "from": "0.1.0",
        "to": "0.2.0",
        "publisher": PLUGIN_KEY_ID,
        "username": ADMIN_USER,
    }
    assert event["category"] == "operativo"
    installed.plugins.enable(PLUGIN)
    assert installed.plugins.get(PLUGIN).version == "0.2.0"


def test_a_second_update_retires_the_older_previous_copy(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    installed.plugins.update_package(platform_token, make_package("v2", "0.2.0"), confirmed=True)
    record = installed.plugins.update_package(
        platform_token, make_package("v3", "0.3.0"), confirmed=True
    )
    assert (record.version, record.previous_version) == ("0.3.0", "0.2.0")
    assert not _stored(installed, PLUGIN, "0.1.0").exists()
    assert _stored(installed, PLUGIN, "0.2.0").is_dir()
    assert _stored(installed, PLUGIN, "0.3.0").is_dir()


def test_rollback_swaps_the_versions_and_rolling_back_again_returns_the_newer(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    installed.plugins.update_package(platform_token, make_package("v2", "0.2.0"), confirmed=True)
    record = installed.plugins.rollback(platform_token, PLUGIN, confirmed=True)
    assert (record.version, record.previous_version) == ("0.1.0", "0.2.0")
    record = installed.plugins.rollback(platform_token, PLUGIN, confirmed=True)
    assert (record.version, record.previous_version) == ("0.2.0", "0.1.0")
    rolled = installed.audit.events_of_type("plugin.rolled_back")
    assert [event["payload"]["to"] for event in rolled] == ["0.1.0", "0.2.0"]
    installed.plugins.enable(PLUGIN)


def test_rollback_cannot_bypass_a_quarantine_of_the_older_version(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    installed.plugins.quarantine(platform_token, PLUGIN, "motivo")
    installed.plugins.update_package(platform_token, make_package("v2", "0.2.0"), confirmed=True)
    installed.plugins.enable(PLUGIN)
    assert installed.plugins.get(PLUGIN).version == "0.2.0"

    installed.plugins.disable(PLUGIN)
    installed.plugins.rollback(platform_token, PLUGIN, confirmed=True)

    record = installed.plugins.get(PLUGIN)
    assert (record.version, record.quarantined) == ("0.1.0", True)
    with pytest.raises(PluginError, match="en cuarentena"):
        installed.plugins.enable(PLUGIN)


def test_uninstall_removes_the_current_and_the_previous_copies(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    installed.plugins.update_package(platform_token, make_package("v2", "0.2.0"), confirmed=True)
    installed.plugins.uninstall(PLUGIN)
    assert installed.plugins.list_plugins() == []
    assert not _stored(installed, PLUGIN, "0.1.0").exists()
    assert not _stored(installed, PLUGIN, "0.2.0").exists()
    assert _database(installed).fetchall("SELECT COUNT(*) FROM plugin_history") == [(0,)]


def test_auditor_can_read_status_but_cannot_change_quarantine(
    installed: Kernel, platform_token: str
) -> None:
    installed.plugins.quarantine(platform_token, PLUGIN, "motivo")
    token = _session(installed, AUDITOR, PASSWORD, reauthenticate=False)
    statuses = installed.plugins.status(token)
    assert [(item.plugin_id, item.quarantined) for item in statuses] == [(PLUGIN, True)]
    with pytest.raises(AuthorizationError, match=PLUGIN_QUARANTINE_RELEASE_PERMISSION):
        installed.plugins.release_quarantine(token, PLUGIN, confirmed=True)


# Negativas: quién no puede hacerlo


def test_operator_cannot_quarantine_update_or_roll_back(
    installed: Kernel, make_package: Callable[..., Path]
) -> None:
    token = _session(installed, OPERATOR, PASSWORD, reauthenticate=True)
    with pytest.raises(AuthorizationError, match=PLUGIN_QUARANTINE_PERMISSION):
        installed.plugins.quarantine(token, PLUGIN, "motivo")
    with pytest.raises(AuthorizationError, match=PLUGIN_VERSION_PERMISSION):
        installed.plugins.update_package(token, make_package("v2", "0.2.0"), confirmed=True)
    assert installed.plugins.get(PLUGIN).version == "0.1.0"
    assert not installed.plugins.get(PLUGIN).quarantined
    denied = installed.audit.events_of_type("operation.denied")
    assert [event["payload"]["permission"] for event in denied[-2:]] == [
        PLUGIN_QUARANTINE_PERMISSION,
        PLUGIN_VERSION_PERMISSION,
    ]


def test_auditor_cannot_quarantine(installed: Kernel) -> None:
    token = _session(installed, AUDITOR, PASSWORD, reauthenticate=True)
    with pytest.raises(AuthorizationError, match=PLUGIN_QUARANTINE_PERMISSION):
        installed.plugins.quarantine(token, PLUGIN, "motivo")
    assert not installed.plugins.get(PLUGIN).quarantined


def test_an_invalid_session_starts_no_quarantine(installed: Kernel) -> None:
    with pytest.raises(SessionError):
        installed.plugins.quarantine("ficha-inventada", PLUGIN, "motivo")
    assert not installed.plugins.get(PLUGIN).quarantined


def test_update_and_rollback_require_confirmation(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    with pytest.raises(AuthorizationError, match="confirmación"):
        installed.plugins.update_package(platform_token, make_package("v2", "0.2.0"))
    installed.plugins.update_package(platform_token, make_package("v2", "0.2.0"), confirmed=True)
    with pytest.raises(AuthorizationError, match="confirmación"):
        installed.plugins.rollback(platform_token, PLUGIN)
    assert installed.plugins.get(PLUGIN).version == "0.2.0"


def test_update_requires_recent_reauthentication(
    installed: Kernel, make_package: Callable[..., Path]
) -> None:
    stale = _session(installed, ADMIN_USER, ADMIN_PASSWORD, reauthenticate=False)
    with pytest.raises(AuthorizationError, match="reautentique"):
        installed.plugins.update_package(stale, make_package("v2", "0.2.0"), confirmed=True)
    assert installed.plugins.get(PLUGIN).version == "0.1.0"


@pytest.mark.parametrize("reason", ["", "   ", "x" * 201])
def test_quarantine_reason_must_have_one_to_200_characters(
    installed: Kernel, platform_token: str, reason: str
) -> None:
    with pytest.raises(ValidationError, match="entre 1 y 200"):
        installed.plugins.quarantine(platform_token, PLUGIN, reason)
    assert not installed.plugins.get(PLUGIN).quarantined


def test_quarantine_and_release_refuse_repeats_and_unknown_plugins(
    installed: Kernel, platform_token: str
) -> None:
    with pytest.raises(PluginError, match="no está en cuarentena"):
        installed.plugins.release_quarantine(platform_token, PLUGIN, confirmed=True)
    installed.plugins.quarantine(platform_token, PLUGIN, "motivo")
    with pytest.raises(PluginError, match="ya está en cuarentena"):
        installed.plugins.quarantine(platform_token, PLUGIN, "otro motivo")
    with pytest.raises(PluginError, match="no instalado"):
        installed.plugins.quarantine(platform_token, "plugin_inexistente", "motivo")


def test_update_is_refused_while_the_plugin_is_enabled(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    installed.plugins.enable(PLUGIN)
    with pytest.raises(PluginError, match="deshabilite"):
        installed.plugins.update_package(
            platform_token, make_package("v2", "0.2.0"), confirmed=True
        )
    assert installed.plugins.get(PLUGIN).version == "0.1.0"


@pytest.mark.parametrize("version", ["0.1.0", "0.0.9"])
def test_update_needs_a_strictly_newer_version(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path], version: str
) -> None:
    with pytest.raises(PluginError, match="no es más nueva"):
        installed.plugins.update_package(
            platform_token, make_package(f"v-{version}", version), confirmed=True
        )
    assert installed.plugins.get(PLUGIN).version == "0.1.0"


def test_update_must_come_from_the_installed_publisher(
    installed: Kernel,
    platform_token: str,
    make_package: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(installed, trust_level="official", key_id=OTHER_KEY, secret=OTHER_SECRET)
    source = make_package("otro", "0.2.0", secret=OTHER_SECRET, key_id=OTHER_KEY)
    with pytest.raises(PluginError, match="no es del editor instalado"):
        installed.plugins.update_package(platform_token, source, confirmed=True)
    assert installed.plugins.get(PLUGIN).version == "0.1.0"


def test_a_version_already_in_the_store_is_not_installed_again(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    installed.plugins.update_package(platform_token, make_package("v2", "0.2.0"), confirmed=True)
    installed.plugins.rollback(platform_token, PLUGIN, confirmed=True)
    with pytest.raises(PluginError, match="ya está en el almacén"):
        installed.plugins.update_package(
            platform_token, make_package("v2-de-nuevo", "0.2.0"), confirmed=True
        )
    assert installed.plugins.get(PLUGIN).version == "0.1.0"


def test_a_tampered_package_is_rejected_and_the_installed_version_stays(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    source = make_package("alterado", "0.2.0")
    (source / "datos.txt").write_text("contenido cambiado", encoding="utf-8")
    with pytest.raises(ValidationError):
        installed.plugins.update_package(platform_token, source, confirmed=True)
    assert installed.plugins.get(PLUGIN).version == "0.1.0"
    rejected = installed.audit.events_of_type("plugin.rejected")[-1]
    assert rejected["payload"]["source"] == "alterado"


def test_a_revoked_publisher_cannot_update_or_roll_back(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    installed.plugins.update_package(platform_token, make_package("v2", "0.2.0"), confirmed=True)
    installed.plugins.revoke_publisher(platform_token, PLUGIN_KEY_ID, confirmed=True)
    with pytest.raises(PluginError, match="revocad"):
        installed.plugins.rollback(platform_token, PLUGIN, confirmed=True)
    with pytest.raises((PluginError, ValidationError), match="revocad"):
        installed.plugins.update_package(
            platform_token, make_package("v3", "0.3.0"), confirmed=True
        )
    assert installed.plugins.get(PLUGIN).version == "0.2.0"


def test_rollback_needs_a_previous_version_and_a_disabled_plugin(
    installed: Kernel, platform_token: str
) -> None:
    with pytest.raises(PluginError, match="no tiene una versión anterior"):
        installed.plugins.rollback(platform_token, PLUGIN, confirmed=True)
    installed.plugins.enable(PLUGIN)
    with pytest.raises(PluginError, match="deshabilite"):
        installed.plugins.rollback(platform_token, PLUGIN, confirmed=True)


def test_rollback_refuses_an_altered_previous_copy_and_changes_nothing(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    installed.plugins.update_package(platform_token, make_package("v2", "0.2.0"), confirmed=True)
    (_stored(installed, PLUGIN, "0.1.0") / "datos.txt").write_text("alterado", encoding="utf-8")
    with pytest.raises(PluginError, match="no es válida"):
        installed.plugins.rollback(platform_token, PLUGIN, confirmed=True)
    record = installed.plugins.get(PLUGIN)
    assert (record.version, record.previous_version) == ("0.2.0", "0.1.0")


def test_rollback_reports_a_missing_previous_copy(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    installed.plugins.update_package(platform_token, make_package("v2", "0.2.0"), confirmed=True)
    shutil.rmtree(_stored(installed, PLUGIN, "0.1.0"))
    with pytest.raises(PluginError, match="falta la copia almacenada"):
        installed.plugins.rollback(platform_token, PLUGIN, confirmed=True)
    assert installed.plugins.get(PLUGIN).version == "0.2.0"


# Persistencia: reglas que la base aplica con independencia del código que escribe


def test_the_database_keeps_one_previous_version_and_one_quarantine_per_version(
    installed: Kernel, platform_token: str, make_package: Callable[..., Path]
) -> None:
    installed.plugins.update_package(platform_token, make_package("v2", "0.2.0"), confirmed=True)
    database = _database(installed)
    with pytest.raises(StorageError):
        database.execute(
            "INSERT INTO plugin_history (plugin_id, version, publisher_key_id, integrity_sha256, "
            "dependencies) VALUES (?, ?, ?, ?, ?)",
            (PLUGIN, "0.0.1", PLUGIN_KEY_ID, "0" * 64, "[]"),
        )
    installed.plugins.quarantine(platform_token, PLUGIN, "motivo")
    with pytest.raises(StorageError):
        database.execute(
            "INSERT INTO plugin_quarantine (plugin_id, version, reason, username) "
            "VALUES (?, ?, ?, ?)",
            (PLUGIN, "0.2.0", "otro motivo", ADMIN_USER),
        )


def test_a_quarantine_reason_is_stored_with_the_version_it_blocks(
    installed: Kernel, platform_token: str
) -> None:
    installed.plugins.quarantine(platform_token, PLUGIN, "  motivo recortado  ")
    rows = _database(installed).fetchall(
        "SELECT plugin_id, version, reason, username FROM plugin_quarantine"
    )
    assert rows == [(PLUGIN, "0.1.0", "motivo recortado", ADMIN_USER)]


def test_quarantine_permissions_are_declared_and_only_release_is_critical() -> None:
    assert PLUGIN_QUARANTINE_RELEASE_PERMISSION in CRITICAL_PERMISSIONS
    assert PLUGIN_VERSION_PERMISSION in CRITICAL_PERMISSIONS
    assert PLUGIN_QUARANTINE_PERMISSION not in CRITICAL_PERMISSIONS
