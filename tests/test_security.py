"""Seguridad: contraseñas, cuentas, roles, permisos temporales, sesiones y el guardián."""

from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from natxajo_auditor.core.exceptions import AuthorizationError, SessionError, ValidationError
from natxajo_auditor.core.permissions import parse_permission
from natxajo_auditor.interfaces.terminal.app import run_terminal
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import SERVICE_DATABASE, SERVICE_SECURITY, Kernel
from natxajo_auditor.security.accounts import ACTIVE
from natxajo_auditor.security.passwords import hash_password, validate_policy, verify_password
from natxajo_auditor.storage.database import Database
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER, install_administrator

PASSWORD = "contraseña-de-prueba-1"
ALT_PASSWORD = "otra-contraseña-de-prueba"
SECOND_ADMIN = "admin_segundo"
APPROVER = "aprobador_prueba"
AUDITOR = "auditor_prueba"


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def secure(context: RuntimeContext, clock: FakeClock) -> Iterator[Kernel]:
    instance = Kernel(context, password_iterations=1_000, clock=clock)
    instance.start()
    yield instance
    instance.stop()


def _bootstrap(kernel: Kernel) -> None:
    install_administrator(kernel)


def _database(kernel: Kernel) -> Database:
    return kernel.services.get(SERVICE_DATABASE)  # type: ignore[no-any-return]


def _scripted(answers: Iterable[str]) -> Callable[[str], str]:
    iterator = iter(answers)

    def read(prompt: str) -> str:
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None

    return read


# Contraseñas


def test_password_hash_verifies_and_is_not_stored_in_clear() -> None:
    stored = hash_password(PASSWORD, 1_000)
    assert PASSWORD not in stored
    assert verify_password(PASSWORD, stored)
    assert not verify_password(ALT_PASSWORD, stored)


def test_each_hash_uses_a_new_salt() -> None:
    assert hash_password(PASSWORD, 1_000) != hash_password(PASSWORD, 1_000)


@pytest.mark.parametrize("stored", ["", "basura", "pbkdf2_sha256$x$00$00", "otro$1000$00$00"])
def test_malformed_hashes_never_verify(stored: str) -> None:
    assert not verify_password(PASSWORD, stored)


def test_hash_refuses_too_few_iterations() -> None:
    with pytest.raises(ValueError):
        hash_password(PASSWORD, 10)


@pytest.mark.parametrize(
    ("password", "username"),
    [
        ("corta", "usuario_x"),
        ("aaaaaaaaaaaaaaaaaaaa", "usuario_x"),
        ("            ", "usuario_x"),
        ("admin_prueba", "admin_prueba"),
    ],
)
def test_password_policy_rejects_weak_passwords(password: str, username: str) -> None:
    with pytest.raises(ValidationError):
        validate_policy(password, username)


# Cuentas


def test_account_creation_validates_name_roles_and_duplicates(secure: Kernel) -> None:
    _bootstrap(secure)
    with pytest.raises(ValidationError, match="nombre de usuario no válido"):
        secure.security.create_account("No Valido", PASSWORD, ["auditor"])
    with pytest.raises(ValidationError, match="rol no existe: dios"):
        secure.security.create_account("usuario_uno", PASSWORD, ["dios"])
    with pytest.raises(ValidationError, match="al menos un rol"):
        secure.security.create_account("usuario_uno", PASSWORD, [])
    with pytest.raises(ValidationError, match="ya existe"):
        secure.security.create_account(ADMIN_USER, PASSWORD, ["auditor"])


def test_separation_of_duties_blocks_operator_and_auditor_together(secure: Kernel) -> None:
    _bootstrap(secure)
    with pytest.raises(ValidationError, match="separación de funciones"):
        secure.security.create_account("usuario_uno", PASSWORD, ["operador", "auditor"])
    secure.security.create_account("usuario_dos", PASSWORD, ["operador"])
    with pytest.raises(ValidationError, match="separación de funciones"):
        secure.security.accounts.set_roles("usuario_dos", ["operador", "auditor"])


def test_failed_logins_lock_the_account_until_the_lockout_expires(
    secure: Kernel, clock: FakeClock
) -> None:
    _bootstrap(secure)
    for _ in range(5):
        with pytest.raises(AuthorizationError, match="credenciales no válidas"):
            secure.security.login(ADMIN_USER, "contraseña-incorrecta")
    # Durante el bloqueo ni la contraseña correcta entra, y el mensaje no cambia.
    with pytest.raises(AuthorizationError, match="credenciales no válidas"):
        secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    clock.advance(timedelta(minutes=16))
    assert secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    assert len(secure.audit.events_of_type("account.login_failed")) == 5
    assert len(secure.audit.events_of_type("account.login_blocked")) == 1


def test_unknown_user_gets_the_same_message_as_a_wrong_password(secure: Kernel) -> None:
    _bootstrap(secure)
    with pytest.raises(AuthorizationError, match="credenciales no válidas"):
        secure.security.login("nadie_real", PASSWORD)


def test_locked_account_answers_exactly_like_an_unknown_user(secure: Kernel) -> None:
    _bootstrap(secure)
    secure.security.create_account("usuario_bloqueado", PASSWORD, ["operador"])
    for _ in range(5):
        with pytest.raises(AuthorizationError):
            secure.security.login("usuario_bloqueado", "contraseña-incorrecta")
    with pytest.raises(AuthorizationError) as locked:
        secure.security.login("usuario_bloqueado", PASSWORD)
    with pytest.raises(AuthorizationError) as unknown:
        secure.security.login("nadie_real", PASSWORD)
    assert str(locked.value) == str(unknown.value) == "credenciales no válidas"


def test_a_success_resets_the_failure_counter(secure: Kernel) -> None:
    _bootstrap(secure)
    for _ in range(4):
        with pytest.raises(AuthorizationError):
            secure.security.login(ADMIN_USER, "contraseña-incorrecta")
    secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    for _ in range(4):
        with pytest.raises(AuthorizationError):
            secure.security.login(ADMIN_USER, "contraseña-incorrecta")
    assert secure.security.login(ADMIN_USER, ADMIN_PASSWORD)


def test_disabled_account_cannot_log_in_and_loses_its_sessions(secure: Kernel) -> None:
    _bootstrap(secure)
    secure.security.create_account(SECOND_ADMIN, PASSWORD, ["administrador"])
    token = secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    secure.security.disable_account(ADMIN_USER)
    with pytest.raises(AuthorizationError, match="cuenta deshabilitada"):
        secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    with pytest.raises(SessionError):
        secure.security.sessions.validate(token)
    secure.security.accounts.set_status(ADMIN_USER, ACTIVE)
    assert secure.security.login(ADMIN_USER, ADMIN_PASSWORD)


def test_last_active_administrator_cannot_be_disabled_or_demoted(secure: Kernel) -> None:
    _bootstrap(secure)
    with pytest.raises(ValidationError, match="último administrador activo"):
        secure.security.disable_account(ADMIN_USER)
    with pytest.raises(ValidationError, match="último administrador activo"):
        secure.security.accounts.set_roles(ADMIN_USER, ["auditor"])
    secure.security.create_account(SECOND_ADMIN, PASSWORD, ["administrador"])
    secure.security.accounts.set_roles(ADMIN_USER, ["auditor"])
    assert secure.security.accounts.get(ADMIN_USER).roles == ("auditor",)
    with pytest.raises(ValidationError, match="último administrador activo"):
        secure.security.disable_account(SECOND_ADMIN)


# Sesiones


def test_session_token_is_stored_only_as_a_hash(secure: Kernel) -> None:
    _bootstrap(secure)
    token = secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    rows = _database(secure).fetchall("SELECT token_hash FROM sessions")
    assert len(rows) == 1
    assert token not in str(rows)
    assert len(str(rows[0][0])) == 64


def test_idle_session_expires(secure: Kernel, clock: FakeClock) -> None:
    _bootstrap(secure)
    token = secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    clock.advance(timedelta(minutes=16))
    with pytest.raises(SessionError, match="caducado"):
        secure.security.sessions.validate(token)


def test_activity_renews_the_idle_timeout(secure: Kernel, clock: FakeClock) -> None:
    _bootstrap(secure)
    token = secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    clock.advance(timedelta(minutes=10))
    secure.security.sessions.validate(token)
    clock.advance(timedelta(minutes=10))
    assert secure.security.sessions.validate(token).username == ADMIN_USER


def test_absolute_timeout_expires_even_an_active_session(secure: Kernel, clock: FakeClock) -> None:
    _bootstrap(secure)
    token = secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    with pytest.raises(SessionError):
        for _ in range(60):
            clock.advance(timedelta(minutes=10))
            secure.security.sessions.validate(token)


def test_logout_invalidates_the_token(secure: Kernel) -> None:
    _bootstrap(secure)
    token = secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    secure.security.logout(token)
    with pytest.raises(SessionError):
        secure.security.sessions.validate(token)


def test_concurrent_sessions_are_limited(secure: Kernel) -> None:
    _bootstrap(secure)
    for _ in range(3):
        secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    with pytest.raises(AuthorizationError, match="máximo de 3 sesiones"):
        secure.security.login(ADMIN_USER, ADMIN_PASSWORD)


def test_reauthentication_is_recent_for_five_minutes(secure: Kernel, clock: FakeClock) -> None:
    _bootstrap(secure)
    token = secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    with pytest.raises(AuthorizationError):
        secure.security.reauthenticate(token, "contraseña-incorrecta")
    secure.security.reauthenticate(token, ADMIN_PASSWORD)
    session = secure.security.sessions.validate(token)
    assert secure.security.sessions.recently_reauthenticated(session)
    clock.advance(timedelta(minutes=6))
    session = secure.security.sessions.validate(token)
    assert not secure.security.sessions.recently_reauthenticated(session)


# Roles y permisos


def test_builtin_roles_are_seeded(secure: Kernel) -> None:
    names = {role.name for role in secure.security.roles.all_roles() if role.builtin}
    assert names == {"administrador", "operador", "auditor"}


def test_custom_role_cannot_grant_more_than_its_creator_holds(secure: Kernel) -> None:
    _bootstrap(secure)
    actor = secure.security.authorizer.effective(ADMIN_USER)
    secure.security.roles.create_custom("lector", ["*:*:*:leer"], [], actor)
    auditor_only = frozenset({parse_permission("*:*:*:leer", allow_wildcards=True)})
    with pytest.raises(AuthorizationError, match="no puede conceder"):
        secure.security.roles.create_custom("escritor", ["*:*:*:escribir"], [], auditor_only)


def test_inheritance_is_limited_to_five_levels(secure: Kernel) -> None:
    _bootstrap(secure)
    actor = secure.security.authorizer.effective(ADMIN_USER)
    roles = secure.security.roles
    roles.create_custom("nivel_1", ["auditoria:nucleo:evento:leer"], [], actor)
    parent = "nivel_1"
    for level in range(2, 6):
        roles.create_custom(f"nivel_{level}", [], [parent], actor)
        parent = f"nivel_{level}"
    assert roles.depth("nivel_5") == 5
    with pytest.raises(ValidationError, match="profundidad máxima"):
        roles.create_custom("nivel_6", [], [parent], actor)


def test_unknown_parent_role_is_refused(secure: Kernel) -> None:
    _bootstrap(secure)
    actor = secure.security.authorizer.effective(ADMIN_USER)
    with pytest.raises(ValidationError, match="rol padre no existe"):
        secure.security.roles.create_custom("hijo", [], ["fantasma"], actor)


def test_child_role_inherits_permissions_of_its_ancestors(secure: Kernel) -> None:
    _bootstrap(secure)
    actor = secure.security.authorizer.effective(ADMIN_USER)
    secure.security.roles.create_custom("lector_extendido", [], ["auditor"], actor)
    secure.security.create_account("usuario_lector", PASSWORD, ["lector_extendido"])
    authorizer = secure.security.authorizer
    assert authorizer.is_allowed("usuario_lector", "auditoria:nucleo:evento:leer")
    assert not authorizer.is_allowed("usuario_lector", "auditoria:nucleo:evento:escribir")


def test_auditor_reads_but_cannot_execute(secure: Kernel) -> None:
    _bootstrap(secure)
    secure.security.create_account(AUDITOR, PASSWORD, ["auditor"])
    authorizer = secure.security.authorizer
    assert authorizer.is_allowed(AUDITOR, "versiones:nucleo:version:leer")
    assert not authorizer.is_allowed(AUDITOR, "versiones:nucleo:version:ejecutar")


def test_disabled_account_has_no_permissions(secure: Kernel) -> None:
    _bootstrap(secure)
    secure.security.create_account(SECOND_ADMIN, PASSWORD, ["administrador"])
    assert secure.security.authorizer.is_allowed(ADMIN_USER, "modulos:nucleo:modulo:ejecutar")
    secure.security.disable_account(ADMIN_USER)
    assert not secure.security.authorizer.is_allowed(ADMIN_USER, "modulos:nucleo:modulo:ejecutar")


# Permisos temporales


def _temporary_setup(kernel: Kernel) -> None:
    _bootstrap(kernel)
    kernel.security.create_account(SECOND_ADMIN, PASSWORD, ["administrador"])
    kernel.security.create_account(AUDITOR, PASSWORD, ["auditor"])
    actor = kernel.security.authorizer.effective(ADMIN_USER)
    kernel.security.roles.create_custom(
        "aprobador",
        ["seguridad:nucleo:permiso:aprobar"],
        [],
        actor,
    )
    kernel.security.create_account(APPROVER, PASSWORD, ["aprobador"])


def test_temporary_grant_needs_approval_and_expires(secure: Kernel, clock: FakeClock) -> None:
    _temporary_setup(secure)
    grants = secure.security.grants
    permission = "versiones:nucleo:version:ejecutar"
    grant_id = grants.request(ADMIN_USER, AUDITOR, permission, 30, "rotación de versión")
    assert not secure.security.authorizer.is_allowed(AUDITOR, permission)

    record = grants.approve(SECOND_ADMIN, grant_id, secure.security.authorizer.is_allowed)
    assert record.status == "active"
    assert secure.security.authorizer.is_allowed(AUDITOR, permission)

    clock.advance(timedelta(minutes=31))
    assert not secure.security.authorizer.is_allowed(AUDITOR, permission)


def test_nobody_approves_their_own_request(secure: Kernel) -> None:
    _temporary_setup(secure)
    grants = secure.security.grants
    grant_id = grants.request(SECOND_ADMIN, AUDITOR, "versiones:nucleo:version:ejecutar", 10, "x")
    with pytest.raises(AuthorizationError, match="propia solicitud"):
        grants.approve(SECOND_ADMIN, grant_id, secure.security.authorizer.is_allowed)


def test_approver_cannot_approve_a_permission_it_does_not_hold(secure: Kernel) -> None:
    _temporary_setup(secure)
    grants = secure.security.grants
    grant_id = grants.request(ADMIN_USER, AUDITOR, "modulos:nucleo:modulo:escribir", 10, "prueba")
    with pytest.raises(AuthorizationError, match="no puede aprobar un permiso que no posee"):
        grants.approve(APPROVER, grant_id, secure.security.authorizer.is_allowed)


def test_grant_can_be_rejected_and_revoked(secure: Kernel) -> None:
    _temporary_setup(secure)
    grants = secure.security.grants
    can = secure.security.authorizer.is_allowed
    permission = "versiones:nucleo:version:ejecutar"

    rejected = grants.request(ADMIN_USER, AUDITOR, permission, 10, "descartada")
    assert grants.reject(APPROVER, rejected, can).status == "rejected"

    granted = grants.request(ADMIN_USER, AUDITOR, permission, 10, "temporal")
    grants.approve(SECOND_ADMIN, granted, can)
    assert can(AUDITOR, permission)
    assert grants.revoke(ADMIN_USER, granted, can).status == "revoked"
    assert not can(AUDITOR, permission)


@pytest.mark.parametrize(
    ("permission", "minutes"),
    [
        ("versiones:nucleo:version:ejecutar", 0),
        ("versiones:nucleo:version:ejecutar", 241),
        ("*:*:*:leer", 10),
    ],
)
def test_grant_request_rejects_invalid_values(
    secure: Kernel, permission: str, minutes: int
) -> None:
    _temporary_setup(secure)
    with pytest.raises(ValidationError):
        secure.security.grants.request(ADMIN_USER, AUDITOR, permission, minutes, "motivo")


def test_grant_request_for_unknown_account_is_refused(secure: Kernel) -> None:
    _temporary_setup(secure)
    with pytest.raises(ValidationError, match="la cuenta no existe"):
        secure.security.grants.request(
            ADMIN_USER, "fantasma", "versiones:nucleo:version:ejecutar", 10, "x"
        )


# Guardián de operaciones


def test_guard_runs_allowed_operation_and_audits_it(secure: Kernel) -> None:
    _bootstrap(secure)
    token = secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    result = secure.security.guard.run(token, "nucleo:plataforma:estado:leer", lambda: 42)
    assert result == 42
    executed = secure.audit.events_of_type("operation.executed")
    assert executed[-1]["payload"]["permission"] == "nucleo:plataforma:estado:leer"


def test_guard_denies_missing_permission_and_audits_it(secure: Kernel) -> None:
    _bootstrap(secure)
    secure.security.create_account(AUDITOR, PASSWORD, ["auditor"])
    token = secure.security.login(AUDITOR, PASSWORD)
    secure.security.reauthenticate(token, PASSWORD)
    with pytest.raises(AuthorizationError, match="sin permiso"):
        secure.security.guard.run(
            token, "versiones:nucleo:version:ejecutar", lambda: None, confirmed=True
        )
    assert secure.audit.events_of_type("operation.denied")


def test_critical_operation_needs_confirmation_and_recent_reauthentication(
    secure: Kernel, clock: FakeClock
) -> None:
    _bootstrap(secure)
    token = secure.security.login(ADMIN_USER, ADMIN_PASSWORD)
    critical = "modulos:nucleo:modulo:ejecutar"
    with pytest.raises(AuthorizationError, match="confirmación"):
        secure.security.guard.run(token, critical, lambda: "hecho")
    with pytest.raises(AuthorizationError, match="reautentique"):
        secure.security.guard.run(token, critical, lambda: "hecho", confirmed=True)
    secure.security.reauthenticate(token, ADMIN_PASSWORD)
    assert secure.security.guard.run(token, critical, lambda: "hecho", confirmed=True) == "hecho"
    clock.advance(timedelta(minutes=6))
    with pytest.raises(AuthorizationError, match="reautentique"):
        secure.security.guard.run(token, critical, lambda: "hecho", confirmed=True)


def test_guard_rejects_an_unknown_token(secure: Kernel) -> None:
    _bootstrap(secure)
    with pytest.raises(SessionError):
        secure.security.guard.run("ficha-falsa", "nucleo:plataforma:estado:leer", lambda: None)


# Integración


def test_kernel_registers_the_security_service(secure: Kernel) -> None:
    assert SERVICE_SECURITY in secure.services.names()
    assert secure.security.roles.exists("administrador")


def test_expired_session_returns_to_the_login_prompt(secure: Kernel, clock: FakeClock) -> None:
    _bootstrap(secure)
    answers = iter([ADMIN_USER, "2", ADMIN_USER, "0"])
    secrets = iter([ADMIN_PASSWORD, ADMIN_PASSWORD])

    def read(prompt: str) -> str:
        value = next(answers)
        if value == "2":
            clock.advance(timedelta(minutes=16))
        return value

    lines: list[str] = []
    code = run_terminal(
        secure,
        read=read,
        write=lines.append,
        read_secret=lambda prompt: next(secrets),
    )
    assert code == 0
    assert "La sesión ha caducado. Inicie sesión de nuevo." in lines


def test_terminal_creates_a_grant_request_with_no_special_permission(
    secure: Kernel, tmp_path: Path
) -> None:
    _temporary_setup(secure)
    secure.security.create_account("usuario_nuevo", PASSWORD, ["auditor"])
    lines: list[str] = []
    run_terminal(
        secure,
        read=_scripted(
            [AUDITOR, "15", "usuario_nuevo", "versiones:nucleo:version:leer", "30", "prueba", "0"]
        ),
        write=lines.append,
        read_secret=_scripted([PASSWORD]),
    )
    assert any(line.startswith("Solicitud ") for line in lines)
    assert len(secure.security.grants.list_grants()) == 1
