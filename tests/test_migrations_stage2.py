"""Migraciones 6 a 8: actualización desde una base v5 con datos, reversión, integridad y copia previa."""

from pathlib import Path

import pytest

from natxajo_auditor.core.exceptions import StorageError
from natxajo_auditor.kernel.context import RuntimeContext
from natxajo_auditor.kernel.kernel import Kernel
from natxajo_auditor.security.roles import RoleStore
from natxajo_auditor.storage.database import Database
from natxajo_auditor.storage.migrations import (
    MIGRATIONS,
    Migration,
    apply_migrations,
    rollback_migrations,
)

V5 = MIGRATIONS[:5]


def _v5_database(path: Path) -> Database:
    """Base creada por la versión 5, con una cuenta y dos eventos reales."""
    database = Database(path)
    database.open()
    apply_migrations(database, V5)
    RoleStore(database).ensure_builtins()
    database.execute(
        "INSERT INTO accounts (username, password_hash, status) "
        "VALUES ('admin_viejo', 'hash-antiguo', 'active')"
    )
    database.execute(
        "INSERT INTO account_roles (username, role_name) VALUES ('admin_viejo', 'administrador')"
    )
    database.execute(
        "INSERT INTO audit_events (event_type, payload) "
        "VALUES ('account.created', '{\"username\": \"admin_viejo\"}')"
    )
    database.execute(
        "INSERT INTO audit_events (event_type, payload) "
        "VALUES ('module.enabled', '{\"module\": \"alfa\"}')"
    )
    return database


def test_upgrade_from_v5_keeps_every_row_and_classifies_existing_events(tmp_path: Path) -> None:
    database = _v5_database(tmp_path / "v5.db")
    assert apply_migrations(database) == [6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    # Estrategia explícita: las cuentas previas pertenecen a la plataforma, que existía antes
    # de las empresas. Los eventos previos no reciben empresa: solo los ve la plataforma.
    assert database.fetchall("SELECT username, company_id FROM accounts") == [
        ("admin_viejo", "plataforma")
    ]
    assert database.fetchall("SELECT password_hash, status FROM accounts") == [
        ("hash-antiguo", "active")
    ]
    assert database.fetchall("SELECT role_name FROM account_roles") == [("administrador",)]
    categories = dict(database.fetchall("SELECT event_type, category FROM audit_events"))
    assert categories == {"account.created": "seguridad", "module.enabled": "operativo"}
    assert database.fetchall("SELECT event_id, company_id FROM audit_events") == [
        (None, None),
        (None, None),
    ]
    assert database.fetchall("SELECT state FROM installation WHERE id = 1") == [("completed",)]
    assert database.fetchall("PRAGMA foreign_key_check") == []
    assert database.fetchall("PRAGMA integrity_check") == [("ok",)]
    database.close()


def test_an_empty_v5_database_starts_with_a_pending_installation(tmp_path: Path) -> None:
    database = Database(tmp_path / "vacia.db")
    database.open()
    apply_migrations(database, V5)
    assert apply_migrations(database) == [6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    assert database.fetchall("SELECT state FROM installation WHERE id = 1") == [("pending",)]
    database.close()


def test_rolling_back_to_v5_keeps_accounts_and_events(tmp_path: Path) -> None:
    database = _v5_database(tmp_path / "ida.db")
    apply_migrations(database)
    assert rollback_migrations(database, 5) == [15, 14, 13, 12, 11, 10, 9, 8, 7, 6]
    accounts_columns = {row[1] for row in database.fetchall("PRAGMA table_info(accounts)")}
    assert "company_id" not in accounts_columns
    assert (
        database.fetchall(
            "SELECT name FROM sqlite_master WHERE name IN ('installation', 'event_outbox', "
            "'event_deliveries', 'companies')"
        )
        == []
    )
    assert database.fetchall("SELECT username, status FROM accounts") == [("admin_viejo", "active")]
    assert database.fetchall("SELECT event_type, payload FROM audit_events ORDER BY id") == [
        ("account.created", '{"username": "admin_viejo"}'),
        ("module.enabled", '{"module": "alfa"}'),
    ]
    audit_columns = {row[1] for row in database.fetchall("PRAGMA table_info(audit_events)")}
    assert {"event_id", "category", "company_id", "actor"}.isdisjoint(audit_columns)
    database.close()


def test_reapplying_the_installation_migration_recomputes_its_state(tmp_path: Path) -> None:
    database = _v5_database(tmp_path / "recalculo.db")
    apply_migrations(database)
    assert rollback_migrations(database, 6) == [15, 14, 13, 12, 11, 10, 9, 8, 7]
    assert apply_migrations(database) == [7, 8, 9, 10, 11, 12, 13, 14, 15]
    # Con cuentas existentes, la instalación vuelve a quedar completada y no se reabre.
    assert database.fetchall("SELECT state FROM installation WHERE id = 1") == [("completed",)]
    database.close()


def test_reapplying_after_a_rollback_restores_the_schema(tmp_path: Path) -> None:
    database = _v5_database(tmp_path / "ida_y_vuelta.db")
    apply_migrations(database)
    rollback_migrations(database, 5)
    assert apply_migrations(database) == [6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    assert database.fetchall("SELECT username, company_id FROM accounts") == [
        ("admin_viejo", "plataforma")
    ]
    assert database.fetchall("PRAGMA foreign_key_check") == []
    assert database.fetchall("PRAGMA integrity_check") == [("ok",)]
    database.close()


def test_an_irreversible_migration_blocks_the_rollback_before_anything_changes(
    tmp_path: Path,
) -> None:
    database = _v5_database(tmp_path / "irreversible.db")
    custom = (*V5, Migration(6, "sin_reversion", ("CREATE TABLE sin_reversion (x INTEGER)",)))
    apply_migrations(database, custom)
    with pytest.raises(StorageError, match="no es reversible"):
        rollback_migrations(database, 5, custom)
    assert database.fetchall("SELECT MAX(version) FROM schema_migrations") == [(6,)]
    assert database.fetchall("SELECT name FROM sqlite_master WHERE name = 'sin_reversion'") == [
        ("sin_reversion",)
    ]
    database.close()


def test_the_kernel_copies_an_existing_database_before_migrating_it(
    context: RuntimeContext,
) -> None:
    database = _v5_database(context.storage_dir / "natxajo.db")
    database.close()
    kernel = Kernel(context, password_iterations=1_000)
    kernel.start()
    kernel.stop()
    copies = sorted((context.storage_dir / "migraciones").glob("natxajo-previa-v6-*.db"))
    assert len(copies) == 1
    copy = Database(copies[0])
    copy.open()
    try:
        versions = [row[0] for row in copy.fetchall("SELECT version FROM schema_migrations")]
        assert sorted(versions) == [1, 2, 3, 4, 5]
        assert copy.fetchall("SELECT username FROM accounts") == [("admin_viejo",)]
    finally:
        copy.close()


def test_a_database_without_pending_migrations_is_not_copied(context: RuntimeContext) -> None:
    first = Kernel(context, password_iterations=1_000)
    first.start()
    first.stop()
    second = Kernel(context, password_iterations=1_000)
    second.start()
    second.stop()
    assert list((context.storage_dir / "migraciones").glob("*.db")) == []
