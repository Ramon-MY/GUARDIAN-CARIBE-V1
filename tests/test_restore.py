import sqlite3

import pytest

from scripts.restore_sqlite_backup import restore


def create_database(path, value: str) -> None:
    connection = sqlite3.connect(path)
    try:
        for table in ("users", "security_events", "alerts", "indicators"):
            connection.execute(f"CREATE TABLE {table} (value TEXT)")
        connection.execute("INSERT INTO users(value) VALUES (?)", (value,))
        connection.commit()
    finally:
        connection.close()


def test_restore_requires_confirmation_and_replaces_atomically(tmp_path):
    backup = tmp_path / "backup.sqlite3"
    destination = tmp_path / "guardian.sqlite3"
    create_database(backup, "backup-state")
    create_database(destination, "current-state")

    with pytest.raises(ValueError, match="confirm-replace"):
        restore(backup, destination, confirmed=False)

    restore(backup, destination, confirmed=True)
    with sqlite3.connect(destination) as connection:
        restored = connection.execute("SELECT value FROM users").fetchone()[0]
    assert restored == "backup-state"


def test_restore_rejects_database_missing_project_tables(tmp_path):
    backup = tmp_path / "not-guardian.sqlite3"
    destination = tmp_path / "guardian.sqlite3"
    with sqlite3.connect(backup) as connection:
        connection.execute("CREATE TABLE other(value TEXT)")

    with pytest.raises(ValueError, match="missing expected"):
        restore(backup, destination, confirmed=True)
    assert not destination.exists()
