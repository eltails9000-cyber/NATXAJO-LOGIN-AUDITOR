"""Sesiones: fichas opacas guardadas como hash, caducidad por inactividad y absoluta,
reautenticación y límite de sesiones simultáneas.

La ficha no se guarda en claro: la base de datos solo contiene su SHA-256. Quien lea la base de
datos no puede usar las sesiones activas.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from natxajo_auditor.core.exceptions import SessionError, SessionLimitError
from natxajo_auditor.core.utilities import Clock, from_iso, sha256_bytes, to_iso
from natxajo_auditor.security.accounts import AccountStore
from natxajo_auditor.storage.audit import AuditLog
from natxajo_auditor.storage.database import Database

IDLE_TIMEOUT = timedelta(minutes=15)
ABSOLUTE_TIMEOUT = timedelta(hours=8)
REAUTH_WINDOW = timedelta(minutes=5)
MAX_CONCURRENT_SESSIONS = 3
MAX_LISTED_SESSIONS = 500
INVALID_SESSION = "sesión no válida"


@dataclass(frozen=True)
class Session:
    session_id: int
    username: str
    reauth_at: datetime | None


@dataclass(frozen=True)
class SessionInfo:
    """Estado de una sesión vigente para mostrarlo. No contiene la ficha ni su huella."""

    username: str
    company_id: str
    created_at: str
    last_activity: str
    expires_at: str
    reauthenticated: bool


class SessionStore:
    def __init__(self, database: Database, audit: AuditLog, clock: Clock) -> None:
        self._database = database
        self._audit = audit
        self._clock = clock

    def open(self, username: str) -> str:
        now = self._clock()
        token = secrets.token_urlsafe(32)
        # El recuento y la inserción van en la misma transacción de escritura: dos inicios
        # simultáneos no pueden superar el límite leyendo el mismo número de sesiones.
        with self._database.transaction() as connection:
            if len(self._live_rows(username, now)) >= MAX_CONCURRENT_SESSIONS:
                raise SessionLimitError(
                    f"máximo de {MAX_CONCURRENT_SESSIONS} sesiones simultáneas alcanzado; "
                    "cierre una sesión"
                )
            connection.execute(
                "INSERT INTO sessions (token_hash, username, created_at, last_activity, "
                "expires_at) VALUES (?, ?, ?, ?, ?)",
                (
                    _digest(token),
                    username,
                    to_iso(now),
                    to_iso(now),
                    to_iso(now + ABSOLUTE_TIMEOUT),
                ),
            )
            self._audit.record("session.opened", {"username": username}, connection=connection)
        return token

    def validate(self, token: str) -> Session:
        """Comprueba la sesión y renueva su actividad. Lanza SessionError si no es válida."""
        now = self._clock()
        rows = self._database.fetchall(
            "SELECT id, username, last_activity, expires_at, reauth_at, revoked_at "
            "FROM sessions WHERE token_hash = ?",
            (_digest(token),),
        )
        if not rows:
            raise SessionError(INVALID_SESSION)
        session_id, username, last_text, expires_text, reauth_text, revoked = rows[0]
        if revoked is not None:
            raise SessionError(INVALID_SESSION)
        if not _is_live(str(last_text), str(expires_text), now):
            # La revocación se confirma antes de lanzar el error: dentro de la transacción,
            # el error la revertiría y la sesión caducada seguiría siendo válida en la base.
            with self._database.transaction() as connection:
                connection.execute(
                    "UPDATE sessions SET revoked_at = ? WHERE id = ?", (to_iso(now), session_id)
                )
                self._audit.record(
                    "session.expired", {"username": str(username)}, connection=connection
                )
            raise SessionError("la sesión ha caducado; inicie sesión de nuevo")
        self._database.execute(
            "UPDATE sessions SET last_activity = ? WHERE id = ?", (to_iso(now), session_id)
        )
        return Session(
            session_id=int(str(session_id)),
            username=str(username),
            reauth_at=from_iso(None if reauth_text is None else str(reauth_text)),
        )

    def close(self, token: str) -> None:
        """Cierra una sesión. Es seguro llamarlo con una sesión ya cerrada."""
        now = self._clock()
        rows = self._database.fetchall(
            "SELECT username FROM sessions WHERE token_hash = ? AND revoked_at IS NULL",
            (_digest(token),),
        )
        if not rows:
            return
        with self._database.transaction() as connection:
            connection.execute(
                "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
                (to_iso(now), _digest(token)),
            )
            self._audit.record(
                "session.closed", {"username": str(rows[0][0])}, connection=connection
            )

    def close_all(self, username: str) -> None:
        now = self._clock()
        with self._database.transaction() as connection:
            connection.execute(
                "UPDATE sessions SET revoked_at = ? WHERE username = ? AND revoked_at IS NULL",
                (to_iso(now), username),
            )
            self._audit.record("session.closed_all", {"username": username}, connection=connection)

    def reauthenticate(self, token: str, password: str, accounts: AccountStore) -> None:
        """Vuelve a pedir la contraseña. Un fallo cuenta para el bloqueo de la cuenta."""
        session = self.validate(token)
        accounts.check_password(session.username, password)
        now = self._clock()
        with self._database.transaction() as connection:
            connection.execute(
                "UPDATE sessions SET reauth_at = ? WHERE id = ?", (to_iso(now), session.session_id)
            )
            self._audit.record(
                "session.reauthenticated", {"username": session.username}, connection=connection
            )

    def recently_reauthenticated(self, session: Session) -> bool:
        if session.reauth_at is None:
            return False
        age = self._clock() - session.reauth_at
        return timedelta(0) <= age <= REAUTH_WINDOW

    def list_live(
        self, accounts: AccountStore, *, company_id: str | None = None
    ) -> list[SessionInfo]:
        """Sesiones vigentes, más recientes primero. Con company_id, solo las de esa empresa.

        Es de solo lectura: no renueva la actividad ni cambia nada, y no devuelve fichas ni huellas.
        """
        now = self._clock()
        rows = self._database.fetchall(
            "SELECT username, created_at, last_activity, expires_at, reauth_at FROM sessions "
            "WHERE revoked_at IS NULL ORDER BY id DESC"
        )
        listed: list[SessionInfo] = []
        for username, created, last_activity, expires, reauth in rows:
            if not _is_live(str(last_activity), str(expires), now):
                continue
            name = str(username)
            owner = accounts.company_of(name)
            if company_id is not None and owner != company_id:
                continue
            reauth_at = from_iso(None if reauth is None else str(reauth))
            session = Session(session_id=0, username=name, reauth_at=reauth_at)
            listed.append(
                SessionInfo(
                    username=name,
                    company_id=owner,
                    created_at=str(created),
                    last_activity=str(last_activity),
                    expires_at=str(expires),
                    reauthenticated=self.recently_reauthenticated(session),
                )
            )
            if len(listed) == MAX_LISTED_SESSIONS:
                break
        return listed

    def _live_rows(self, username: str, now: datetime) -> list[tuple[object, ...]]:
        rows = self._database.fetchall(
            "SELECT id, last_activity, expires_at FROM sessions "
            "WHERE username = ? AND revoked_at IS NULL",
            (username,),
        )
        return [row for row in rows if _is_live(str(row[1]), str(row[2]), now)]


def _is_live(last_activity: str, expires_at: str, now: datetime) -> bool:
    last = from_iso(last_activity)
    expires = from_iso(expires_at)
    if last is None or expires is None:
        return False
    return now < expires and now - last <= IDLE_TIMEOUT


def _digest(token: str) -> str:
    return sha256_bytes(token.encode("utf-8"))
