"""Cuentas: alta, autenticación con bloqueo temporal, estado, roles y empresa.

Un error de inicio de sesión no revela si el usuario existe. Tras MAX_FAILED_ATTEMPTS fallos
seguidos la cuenta queda bloqueada durante LOCKOUT. Mientras dura el bloqueo, cualquier intento
recibe el mismo mensaje que una contraseña incorrecta, también la contraseña correcta. Un acierto
reinicia el contador.

Cada cuenta pertenece a una empresa desde su creación. La empresa no puede cambiarse.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from natxajo_auditor.core.contracts import PLATFORM_COMPANY
from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.core.utilities import Clock, from_iso, to_iso
from natxajo_auditor.security.passwords import hash_password, validate_policy, verify_password
from natxajo_auditor.security.roles import ADMINISTRATOR, check_separation
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database

USERNAME = re.compile(r"[a-z][a-z0-9_.-]{2,39}")
MAX_FAILED_ATTEMPTS = 5
LOCKOUT = timedelta(minutes=15)
INVALID_CREDENTIALS = "credenciales no válidas"
ACTIVE = "active"
DISABLED = "disabled"
PENDING_INSTALLATION = "pending"
_DUMMY_PASSWORD = "contraseña-ficticia-para-igualar-tiempos"
_ACCEPTED = "aceptada"
_REJECTED = "rechazada"
_DISABLED = "deshabilitada"


@dataclass(frozen=True)
class Account:
    username: str
    status: str
    roles: tuple[str, ...]
    company_id: str


class AccountStore:
    def __init__(
        self,
        database: Database,
        audit: AuditLog,
        clock: Clock,
        iterations: int,
    ) -> None:
        self._database = database
        self._audit = audit
        self._clock = clock
        self._iterations = iterations
        self._dummy_hash: str | None = None

    def count(self) -> int:
        rows = self._database.fetchall("SELECT COUNT(*) FROM accounts")
        return int(rows[0][0])

    def find(self, username: str) -> Account | None:
        rows = self._database.fetchall(
            "SELECT username, status, company_id FROM accounts WHERE username = ?", (username,)
        )
        if not rows:
            return None
        roles = self._database.fetchall(
            "SELECT role_name FROM account_roles WHERE username = ? ORDER BY role_name",
            (username,),
        )
        return Account(
            username=str(rows[0][0]),
            status=str(rows[0][1]),
            roles=tuple(str(row[0]) for row in roles),
            company_id=str(rows[0][2]),
        )

    def get(self, username: str) -> Account:
        account = self.find(username)
        if account is None:
            raise ValidationError(f"la cuenta no existe: {username}")
        return account

    def accounts(self, company_id: str | None = None) -> list[Account]:
        """Cuentas ordenadas por usuario. Con company_id, solo las de esa empresa."""
        if company_id is None:
            rows = self._database.fetchall("SELECT username FROM accounts ORDER BY username")
        else:
            rows = self._database.fetchall(
                "SELECT username FROM accounts WHERE company_id = ? ORDER BY username",
                (company_id,),
            )
        return [self.get(str(row[0])) for row in rows]

    def company_of(self, username: str) -> str:
        rows = self._database.fetchall(
            "SELECT company_id FROM accounts WHERE username = ?", (username,)
        )
        if not rows:
            raise ValidationError(f"la cuenta no existe: {username}")
        return str(rows[0][0])

    def installation_pending(self) -> bool:
        rows = self._database.fetchall("SELECT state FROM installation WHERE id = 1")
        return any(str(row[0]) == PENDING_INSTALLATION for row in rows)

    def create(
        self,
        username: str,
        password: str,
        roles: Iterable[str],
        company_id: str = PLATFORM_COMPANY,
    ) -> Account:
        """Crea una cuenta en una empresa. Antes hay que completar la instalación inicial."""
        if self.installation_pending():
            raise ValidationError("complete la instalación inicial antes de crear cuentas")
        role_names = self.prepare_new(username, password, roles, company_id)
        with self._database.transaction() as connection:
            self.insert_in(connection, username, password, company_id, role_names)
        return self.get(username)

    def prepare_new(
        self, username: str, password: str, roles: Iterable[str], company_id: str
    ) -> tuple[str, ...]:
        """Valida una cuenta nueva sin escribir nada. Devuelve los roles sin repetir."""
        if not USERNAME.fullmatch(username):
            raise ValidationError(
                f"nombre de usuario no válido: {username} (minúsculas, dígitos, punto, guion y "
                "guion bajo; de 3 a 40 caracteres)"
            )
        role_names = tuple(dict.fromkeys(roles))
        if not role_names:
            raise ValidationError("la cuenta debe tener al menos un rol")
        check_separation(role_names)
        validate_policy(password, username)
        if not self._company_exists(company_id):
            raise ValidationError(f"la empresa no existe: {company_id}")
        if self.find(username) is not None:
            raise ValidationError(f"la cuenta ya existe: {username}")
        for role in role_names:
            if not self._role_exists(role):
                raise ValidationError(f"rol no existe: {role}")
        return role_names

    def insert_in(
        self,
        connection: sqlite3.Connection,
        username: str,
        password: str,
        company_id: str,
        role_names: tuple[str, ...],
    ) -> None:
        """Escribe la cuenta, sus roles y su evento dentro de una transacción ya abierta."""
        hashed = hash_password(password, self._iterations)
        connection.execute(
            "INSERT INTO accounts (username, password_hash, status, company_id) "
            "VALUES (?, ?, ?, ?)",
            (username, hashed, ACTIVE, company_id),
        )
        for role in role_names:
            connection.execute(
                "INSERT INTO account_roles (username, role_name) VALUES (?, ?)",
                (username, role),
            )
        self._audit.record(
            "account.created",
            {"username": username, "roles": list(role_names)},
            connection=connection,
            company_id=company_id,
        )

    def check_password(self, username: str, password: str) -> Account:
        """Comprueba la contraseña, aplica el bloqueo y devuelve la cuenta si todo es correcto."""
        now = self._clock()
        rows = self._database.fetchall(
            "SELECT password_hash FROM accounts WHERE username = ?", (username,)
        )
        if not rows:
            # Mismo coste que una cuenta real, para no revelar qué usuarios existen.
            verify_password(password, self._dummy())
            raise AuthorizationError(INVALID_CREDENTIALS)
        # La contraseña se verifica siempre, también durante un bloqueo, con el mismo coste.
        verified = verify_password(password, str(rows[0][0]))
        outcome = self._register_attempt(username, verified, now)
        if outcome == _DISABLED:
            raise AuthorizationError("cuenta deshabilitada")
        if outcome != _ACCEPTED:
            raise AuthorizationError(INVALID_CREDENTIALS)
        return self.get(username)

    def _register_attempt(self, username: str, verified: bool, now: datetime) -> str:
        """Decide el intento y lo registra dentro de una transacción de escritura.

        Leer el contador y el bloqueo dentro de la misma transacción evita que dos intentos
        solapados pierdan incrementos, o que un acierto salte un bloqueo que otro intento acaba
        de fijar. Los errores se devuelven y se lanzan fuera de la transacción: si no, se
        revertiría el registro del intento.
        """
        with self._database.transaction() as connection:
            row = connection.execute(
                "SELECT status, failed_attempts, locked_until FROM accounts WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                return _REJECTED
            status, failed_text, locked_text = row
            locked_until = from_iso(None if locked_text is None else str(locked_text))
            if locked_until is not None and locked_until > now:
                # Mismo mensaje que una contraseña incorrecta: el bloqueo no revela la cuenta.
                self._audit.record(
                    "account.login_blocked", {"username": username}, connection=connection
                )
                return _REJECTED
            if not verified:
                failed = int(failed_text) + 1
                locked = failed >= MAX_FAILED_ATTEMPTS
                connection.execute(
                    "UPDATE accounts SET failed_attempts = ?, locked_until = ?, "
                    "updated_at = CURRENT_TIMESTAMP WHERE username = ?",
                    (0 if locked else failed, to_iso(now + LOCKOUT) if locked else None, username),
                )
                self._audit.record(
                    "account.login_failed",
                    {"username": username, "locked": locked},
                    connection=connection,
                )
                return _REJECTED
            connection.execute(
                "UPDATE accounts SET failed_attempts = 0, locked_until = NULL, "
                "updated_at = CURRENT_TIMESTAMP WHERE username = ?",
                (username,),
            )
            if str(status) != ACTIVE:
                return _DISABLED
            self._audit.record(
                "account.authenticated", {"username": username}, connection=connection
            )
            return _ACCEPTED

    def set_status(self, username: str, status: str) -> None:
        if status not in (ACTIVE, DISABLED):
            raise ValidationError(f"estado de cuenta no válido: {status}")
        account = self.get(username)
        if status == DISABLED and ADMINISTRATOR in account.roles:
            self._ensure_another_administrator(username)
        with self._database.transaction() as connection:
            connection.execute(
                "UPDATE accounts SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
                (status, username),
            )
            self._audit.record(
                "account.status_changed",
                {"username": username, "status": status},
                connection=connection,
            )

    def change_password(self, username: str, new_password: str) -> None:
        self.get(username)
        validate_policy(new_password, username)
        hashed = hash_password(new_password, self._iterations)
        with self._database.transaction() as connection:
            connection.execute(
                "UPDATE accounts SET password_hash = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE username = ?",
                (hashed, username),
            )
            self._audit.record(
                "account.password_changed", {"username": username}, connection=connection
            )

    def set_roles(
        self, username: str, roles: Iterable[str], *, actor: str | None = None
    ) -> Account:
        """Sustituye los roles de una cuenta. Se aplica la separación de funciones.

        Vía interna: no comprueba quién la pide. `actor` deja constancia en la auditoría de quién
        hizo el cambio; la comprobación la hace SecurityService.change_roles.
        """
        account = self.get(username)
        role_names = tuple(dict.fromkeys(roles))
        if not role_names:
            raise ValidationError("la cuenta debe tener al menos un rol")
        check_separation(role_names)
        for role in role_names:
            if not self._role_exists(role):
                raise ValidationError(f"rol no existe: {role}")
        if ADMINISTRATOR in account.roles and ADMINISTRATOR not in role_names:
            self._ensure_another_administrator(username)
        with self._database.transaction() as connection:
            connection.execute("DELETE FROM account_roles WHERE username = ?", (username,))
            for role in role_names:
                connection.execute(
                    "INSERT INTO account_roles (username, role_name) VALUES (?, ?)",
                    (username, role),
                )
            self._audit.record(
                "account.roles_changed",
                {"username": username, "roles": list(role_names)},
                connection=connection,
                actor=actor,
            )
        return self.get(username)

    def _company_exists(self, company_id: str) -> bool:
        return bool(self._database.fetchall("SELECT 1 FROM companies WHERE id = ?", (company_id,)))

    def _role_exists(self, role: str) -> bool:
        return bool(self._database.fetchall("SELECT 1 FROM roles WHERE name = ?", (role,)))

    def _ensure_another_administrator(self, username: str) -> None:
        """Impide dejar la plataforma sin ningún administrador activo distinto de username."""
        rows = self._database.fetchall(
            "SELECT COUNT(*) FROM account_roles ar JOIN accounts a ON a.username = ar.username "
            "WHERE ar.role_name = ? AND a.status = ? AND ar.username <> ?",
            (ADMINISTRATOR, ACTIVE, username),
        )
        if int(rows[0][0]) == 0:
            raise ValidationError(
                "no se puede quitar el último administrador activo de la plataforma"
            )

    def _dummy(self) -> str:
        if self._dummy_hash is None:
            self._dummy_hash = hash_password(_DUMMY_PASSWORD, self._iterations)
        return self._dummy_hash
