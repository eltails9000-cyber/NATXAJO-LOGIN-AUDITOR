"""Instalador de la primera cuenta de administrador, con código de un solo uso.

Flujo:
1. Mientras la instalación está `pending`, el núcleo puede emitir un código (`issue_code`). El
   código tiene 128 bits de entropía, se muestra una vez y solo se guarda su hash PBKDF2.
2. `complete` comprueba el código dentro de una transacción de escritura. Si es correcto, crea la
   cuenta de administrador de la plataforma y marca la instalación como `completed` en la misma
   transacción. El código queda invalidado.
3. Una instalación `completed` no admite más códigos ni más cambios. Un disparador de la base de
   datos lo garantiza aunque se acceda directamente a la tabla.

Límites: el código caduca a los CODE_TTL. Tras MAX_CODE_ATTEMPTS intentos fallidos hay que
emitir otro. Emitir un código nuevo invalida el anterior.
"""

from __future__ import annotations

import secrets
import sqlite3
from datetime import timedelta

from natxajo_auditor.core.contracts import PLATFORM_COMPANY
from natxajo_auditor.core.exceptions import AuthorizationError, ValidationError
from natxajo_auditor.core.utilities import Clock, from_iso, to_iso
from natxajo_auditor.security.accounts import PENDING_INSTALLATION, Account, AccountStore
from natxajo_auditor.security.passwords import hash_password, verify_password
from natxajo_auditor.security.roles import ADMINISTRATOR
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database

CODE_TTL = timedelta(minutes=30)
MAX_CODE_ATTEMPTS = 5
CODE_BYTES = 16
COMPLETED = "completed"


class Installer:
    def __init__(
        self,
        database: Database,
        audit: AuditLog,
        clock: Clock,
        iterations: int,
        accounts: AccountStore,
    ) -> None:
        self._database = database
        self._audit = audit
        self._clock = clock
        self._iterations = iterations
        self._accounts = accounts

    @property
    def code_ttl(self) -> timedelta:
        """Tiempo de validez de un código de instalación."""
        return CODE_TTL

    @property
    def max_code_attempts(self) -> int:
        """Intentos fallidos permitidos antes de invalidar el código."""
        return MAX_CODE_ATTEMPTS

    def is_pending(self) -> bool:
        return self._accounts.installation_pending()

    def issue_code(self) -> str:
        """Emite un código nuevo y lo devuelve una sola vez. Invalida el anterior."""
        if not self.is_pending():
            raise ValidationError("la instalación ya está completada")
        code = secrets.token_urlsafe(CODE_BYTES)
        hashed = hash_password(code, self._iterations)
        expires = self._clock() + CODE_TTL
        with self._database.transaction() as connection:
            if self._read(connection)[0] != PENDING_INSTALLATION:
                raise ValidationError("la instalación ya está completada")
            connection.execute(
                "UPDATE installation SET code_hash = ?, code_expires_at = ?, "
                "code_failed_attempts = 0, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
                (hashed, to_iso(expires)),
            )
            self._audit.record("installation.code_issued", {}, connection=connection)
        return code

    def complete(self, code: str, username: str, password: str) -> Account:
        """Crea el administrador de la plataforma y cierra la instalación. Un solo uso."""
        if self._accounts.count() > 0:
            raise ValidationError("ya existen cuentas; la instalación no puede repetirse")
        role_names = self._accounts.prepare_new(
            username, password, [ADMINISTRATOR], PLATFORM_COMPANY
        )
        now = self._clock()
        rejected_attempts: int | None = None
        with self._database.transaction() as connection:
            state, code_hash, expires_text, failed = self._read(connection)
            if state == COMPLETED:
                raise ValidationError("la instalación ya está completada")
            if code_hash is None:
                raise ValidationError(
                    "no hay un código de instalación activo; reinicie la instalación"
                )
            expires = None if expires_text is None else from_iso(expires_text)
            if expires is None or expires <= now:
                raise ValidationError(
                    "el código de instalación ha caducado; reinicie la instalación"
                )
            if failed >= MAX_CODE_ATTEMPTS:
                raise ValidationError(
                    "el código de instalación está bloqueado tras demasiados intentos; "
                    "reinicie la instalación"
                )
            if not verify_password(code, code_hash):
                # El contador debe quedar guardado aunque el código sea incorrecto. Por eso el
                # error se lanza fuera de la transacción.
                rejected_attempts = failed + 1
                connection.execute(
                    "UPDATE installation SET code_failed_attempts = ?, "
                    "updated_at = CURRENT_TIMESTAMP WHERE id = 1",
                    (rejected_attempts,),
                )
                self._audit.record(
                    "installation.code_rejected",
                    {"intentos": rejected_attempts},
                    connection=connection,
                )
            else:
                self._accounts.insert_in(
                    connection, username, password, PLATFORM_COMPANY, role_names
                )
                connection.execute(
                    "UPDATE installation SET state = ?, code_hash = NULL, code_expires_at = NULL, "
                    "completed_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
                    (COMPLETED, to_iso(now)),
                )
                self._audit.record(
                    "installation.completed", {"username": username}, connection=connection
                )
        if rejected_attempts is not None:
            left = MAX_CODE_ATTEMPTS - rejected_attempts
            raise AuthorizationError(f"código de instalación no válido ({left} intentos restantes)")
        return self._accounts.get(username)

    def _read(self, connection: sqlite3.Connection) -> tuple[str, str | None, str | None, int]:
        cursor = connection.execute(
            "SELECT state, code_hash, code_expires_at, code_failed_attempts "
            "FROM installation WHERE id = 1"
        )
        row = cursor.fetchone()
        if row is None:
            raise ValidationError("la tabla de instalación no tiene su fila inicial")
        return (
            str(row[0]),
            None if row[1] is None else str(row[1]),
            None if row[2] is None else str(row[2]),
            int(row[3]),
        )
