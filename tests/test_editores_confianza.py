"""Editores de confianza (P-05): autorización en la capa de servicio y de persistencia.

Cubre el alta, la revocación y la revisión de terceros: quién puede hacerlas, en qué ámbito, con
qué confirmación, qué queda auditado y qué reglas aplica la base de datos.
"""

import inspect
import threading
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from natxajo_auditor.core import ed25519
from natxajo_auditor.core.contracts import SCOPE_DENIED
from natxajo_auditor.core.exceptions import (
    AuthorizationError,
    PluginError,
    SessionError,
    StorageError,
    ValidationError,
)
from natxajo_auditor.kernel.kernel import SERVICE_DATABASE, Kernel
from natxajo_auditor.plugins.manager import PluginManager
from natxajo_auditor.plugins.trust import TrustStore
from natxajo_auditor.security.guard import CRITICAL_PERMISSIONS
from natxajo_auditor.storage.database import Database
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER

PASSWORD = "contraseña-de-prueba-2"
PUBLISHER_PERMISSION = "plugins:nucleo:editor:administrar"
REVIEW_PERMISSION = "plugins:nucleo:revision:administrar"
PUBLIC_KEY = ed25519.public_key(bytes(range(1, 33)))
EDITOR = "editor_global"


def _database(kernel: Kernel) -> Database:
    return cast(Database, kernel.services.get(SERVICE_DATABASE))


def _session(kernel: Kernel, username: str, password: str, *, reauthenticate: bool) -> str:
    token = kernel.security.login(username, password)
    if reauthenticate:
        kernel.security.reauthenticate(token, password)
    return token


def _register(
    kernel: Kernel,
    token: str,
    *,
    key_id: str = EDITOR,
    trust_level: str = "verified",
    confirmed: bool = True,
) -> None:
    kernel.plugins.register_publisher(
        token,
        key_id=key_id,
        display_name="Editor global",
        public_key=PUBLIC_KEY,
        trust_level=trust_level,
        confirmed=confirmed,
    )


def _publisher_rows(kernel: Kernel) -> list[str]:
    return [item.key_id for item in kernel.plugins.trust.publishers()]


@pytest.fixture
def world(kernel: Kernel, platform_token: str) -> Kernel:
    """Plataforma con una empresa, una administradora de empresa, un operador y un auditor."""
    security = kernel.security
    security.companies.create("acme", "Acme S.A.")
    security.create_account("admin_acme", PASSWORD, ["administrador"], "acme")
    security.create_account("operador_plataforma", PASSWORD, ["operador"])
    security.create_account("auditor_plataforma", PASSWORD, ["auditor"])
    return kernel


# Positivas


def test_platform_administrator_registers_a_publisher_and_the_audit_names_the_account(
    world: Kernel, platform_token: str
) -> None:
    _register(world, platform_token, trust_level="verified")
    assert _publisher_rows(world) == [EDITOR]
    registered = world.audit.events_of_type("plugin.publisher_registered")
    assert len(registered) == 1
    assert registered[0]["payload"] == {
        "publisher": EDITOR,
        "trust_level": "verified",
        "username": ADMIN_USER,
    }
    assert registered[0]["category"] == "seguridad"


def test_platform_administrator_revokes_a_publisher_and_the_audit_names_the_account(
    world: Kernel, platform_token: str
) -> None:
    _register(world, platform_token)
    disabled = world.plugins.revoke_publisher(platform_token, EDITOR, confirmed=True)
    assert disabled == []
    assert world.plugins.trust.get_publisher(EDITOR).trust_level == "revoked"
    revoked = world.audit.events_of_type("plugin.publisher_revoked")
    assert revoked[-1]["payload"] == {"publisher": EDITOR, "disabled": [], "username": ADMIN_USER}


def test_revoking_twice_is_refused_and_writes_one_revocation(
    world: Kernel, platform_token: str
) -> None:
    _register(world, platform_token)
    world.plugins.revoke_publisher(platform_token, EDITOR, confirmed=True)
    with pytest.raises(PluginError, match="ya está revocado"):
        world.plugins.revoke_publisher(platform_token, EDITOR, confirmed=True)
    assert len(world.audit.events_of_type("plugin.publisher_revoked")) == 1


# Negativas: quién no puede hacerlo


def test_operator_cannot_register_a_publisher(world: Kernel) -> None:
    token = _session(world, "operador_plataforma", PASSWORD, reauthenticate=True)
    with pytest.raises(AuthorizationError, match=PUBLISHER_PERMISSION):
        _register(world, token)
    assert _publisher_rows(world) == []
    denied = world.audit.events_of_type("operation.denied")
    assert denied[-1]["payload"]["username"] == "operador_plataforma"
    assert denied[-1]["payload"]["permission"] == PUBLISHER_PERMISSION


def test_auditor_cannot_revoke_a_publisher(world: Kernel, platform_token: str) -> None:
    _register(world, platform_token)
    token = _session(world, "auditor_plataforma", PASSWORD, reauthenticate=True)
    with pytest.raises(AuthorizationError):
        world.plugins.revoke_publisher(token, EDITOR, confirmed=True)
    assert world.plugins.trust.get_publisher(EDITOR).trust_level == "verified"


def test_company_administrator_cannot_change_global_trust(world: Kernel) -> None:
    token = _session(world, "admin_acme", PASSWORD, reauthenticate=True)
    with pytest.raises(AuthorizationError, match=SCOPE_DENIED):
        _register(world, token)
    assert _publisher_rows(world) == []
    denied = world.audit.events_of_type("operation.denied")
    assert denied[-1]["payload"]["username"] == "admin_acme"
    assert denied[-1]["payload"]["reason"] == SCOPE_DENIED
    assert denied[-1]["company_id"] == "acme"


def test_invalid_session_starts_no_trust_operation(world: Kernel) -> None:
    with pytest.raises(SessionError):
        _register(world, "ficha-inventada")
    assert _publisher_rows(world) == []
    assert world.audit.events_of_type("plugin.publisher_registered") == []


def test_registration_requires_explicit_confirmation(world: Kernel, platform_token: str) -> None:
    with pytest.raises(AuthorizationError, match="confirmación"):
        _register(world, platform_token, confirmed=False)
    assert _publisher_rows(world) == []


def test_registration_requires_recent_reauthentication(world: Kernel) -> None:
    token = _session(world, ADMIN_USER, ADMIN_PASSWORD, reauthenticate=False)
    with pytest.raises(AuthorizationError, match="reautentique"):
        _register(world, token)
    assert _publisher_rows(world) == []
    world.security.reauthenticate(token, ADMIN_PASSWORD)
    _register(world, token)
    assert _publisher_rows(world) == [EDITOR]


def test_a_package_cannot_declare_its_own_trust_level(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
) -> None:
    register_publisher(kernel, trust_level="third_party")
    source = make_plugin_source(tmp_path / "pkg", trust_level="official")
    with pytest.raises(ValidationError, match="campos desconocidos"):
        kernel.plugins.install_package(source)
    assert kernel.plugins.list_plugins() == []


# Escalada de privilegios


def test_operator_cannot_approve_its_own_trust_permission(
    world: Kernel, platform_token: str
) -> None:
    grants = world.security.grants
    can = world.security.authorizer.is_allowed
    requested = grants.request(
        "operador_plataforma", "operador_plataforma", PUBLISHER_PERMISSION, 30, "prueba"
    )
    with pytest.raises(AuthorizationError, match="propia solicitud"):
        grants.approve("operador_plataforma", requested, can)
    with pytest.raises(AuthorizationError):
        _register(world, _session(world, "operador_plataforma", PASSWORD, reauthenticate=True))
    assert _publisher_rows(world) == []

    grants.approve(ADMIN_USER, requested, can)
    token = _session(world, "operador_plataforma", PASSWORD, reauthenticate=True)
    _register(world, token)
    assert _publisher_rows(world) == [EDITOR]
    assert world.audit.events_of_type("grant.approved")[-1]["payload"]["approver"] == ADMIN_USER


def test_review_names_the_session_account_and_is_refused_to_operators(
    kernel: Kernel,
    tmp_path: Path,
    make_plugin_source: Callable[..., Path],
    register_publisher: Callable[..., None],
    platform_token: str,
) -> None:
    register_publisher(kernel, trust_level="third_party")
    kernel.plugins.install_package(make_plugin_source(tmp_path / "pkg"))
    kernel.security.create_account("operador_revision", PASSWORD, ["operador"])
    operator = _session(kernel, "operador_revision", PASSWORD, reauthenticate=True)
    sha = kernel.plugins.get("plugin_ejemplo").integrity_sha256
    with pytest.raises(AuthorizationError, match=REVIEW_PERMISSION):
        kernel.plugins.record_review(
            operator, "plugin_ejemplo", "approved", "", reviewed_sha256=sha, confirmed=True
        )
    assert not kernel.plugins.get("plugin_ejemplo").approved_review

    kernel.plugins.record_review(
        platform_token,
        "plugin_ejemplo",
        "approved",
        "correcto",
        reviewed_sha256=sha,
        confirmed=True,
    )
    assert kernel.plugins.get("plugin_ejemplo").approved_review
    reviewed = kernel.audit.events_of_type("plugin.reviewed")
    assert reviewed[-1]["payload"]["reviewer"] == ADMIN_USER


# Persistencia: reglas que la base aplica con independencia del código que escribe


def test_stored_publisher_key_cannot_change_and_publishers_are_not_deleted(
    world: Kernel, platform_token: str
) -> None:
    _register(world, platform_token)
    database = _database(world)
    with pytest.raises(StorageError, match="inmutable"):
        database.execute(
            "UPDATE plugin_publishers SET public_key = ? WHERE key_id = ?",
            ("AAAA", EDITOR),
        )
    with pytest.raises(StorageError, match="no se eliminan"):
        database.execute("DELETE FROM plugin_publishers WHERE key_id = ?", (EDITOR,))
    assert world.plugins.trust.get_publisher(EDITOR).public_key == PUBLIC_KEY


def test_a_revoked_publisher_cannot_be_reactivated_with_sql(
    world: Kernel, platform_token: str
) -> None:
    _register(world, platform_token)
    world.plugins.revoke_publisher(platform_token, EDITOR, confirmed=True)
    with pytest.raises(StorageError, match="no puede volver a estar activo"):
        _database(world).execute(
            "UPDATE plugin_publishers SET trust_level = 'verified' WHERE key_id = ?", (EDITOR,)
        )
    assert world.plugins.trust.get_publisher(EDITOR).trust_level == "revoked"


# Concurrencia: dos conexiones distintas sobre la misma base de datos


def _race(workers: int, attempt: Callable[[Database], str], path: Path) -> list[str]:
    """Lanza workers hilos que intentan la misma operación a la vez, cada uno con su conexión."""
    barrier = threading.Barrier(workers)
    outcomes: list[str] = []
    lock = threading.Lock()

    def run() -> None:
        database = Database(path)
        database.open()
        try:
            barrier.wait()
            result = attempt(database)
        except (PluginError, StorageError) as exc:
            # Un error de la lógica de confianza es un resultado de la carrera, no un fallo del
            # arnés. Cualquier otro error no aparece en outcomes y la aserción lo detecta.
            result = type(exc).__name__
        finally:
            database.close()
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=run) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    return sorted(outcomes)


def test_concurrent_registrations_of_the_same_publisher_store_one(kernel: Kernel) -> None:
    path = kernel.context.storage_dir / "natxajo.db"

    def attempt(database: Database) -> str:
        store = TrustStore(database)
        with database.transaction() as connection:
            store._insert(connection, "editor_carrera", "Editor", PUBLIC_KEY, "verified")
        return "registrado"

    outcomes = _race(2, attempt, path)
    assert outcomes == ["PluginError", "registrado"]
    assert _publisher_rows(kernel) == ["editor_carrera"]


def test_concurrent_revocations_of_the_same_publisher_store_one(
    world: Kernel, platform_token: str
) -> None:
    _register(world, platform_token)
    path = world.context.storage_dir / "natxajo.db"

    def attempt(database: Database) -> str:
        store = TrustStore(database)
        with database.transaction() as connection:
            store._revoke(connection, EDITOR)
        return "revocado"

    outcomes = _race(2, attempt, path)
    assert outcomes == ["PluginError", "revocado"]
    assert world.plugins.trust.get_publisher(EDITOR).trust_level == "revoked"


# Regresión: no queda ninguna ruta pública que escriba confianza sin la puerta de operaciones


def test_no_public_write_path_remains_for_trust(kernel: Kernel) -> None:
    assert not hasattr(TrustStore, "add_publisher")
    assert not hasattr(TrustStore, "revoke")
    for name in ("register_publisher", "revoke_publisher", "record_review"):
        parameters = list(inspect.signature(getattr(PluginManager, name)).parameters)
        assert parameters[1] == "token", name


def test_every_trust_permission_is_critical() -> None:
    assert PUBLISHER_PERMISSION in CRITICAL_PERMISSIONS
    assert REVIEW_PERMISSION in CRITICAL_PERMISSIONS
