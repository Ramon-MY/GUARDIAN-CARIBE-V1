"""Restore a verified local SQLite backup after stopping the API process."""

import argparse
import json
import os
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path

REQUIRED_TABLES = {"users", "security_events", "alerts", "indicators", "audit_logs"}


def verify_database(path: Path) -> None:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        result = connection.execute("PRAGMA integrity_check").fetchone()
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    finally:
        connection.close()
    if result is None or result[0] != "ok":
        raise ValueError("SQLite integrity check failed")
    missing = REQUIRED_TABLES - tables
    if missing:
        raise ValueError(f"Backup is missing expected GUARDIÁN CARIBE tables: {sorted(missing)}")


def record_restore(path: Path, backup: Path, destination: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_logs)")}
        required = {"actor_id", "action", "resource_type", "resource_id", "occurred_at"}
        if not required.issubset(columns):
            raise ValueError("Backup audit log schema is unsupported; restore was not applied")
        fields = ["actor_id", "action", "resource_type", "resource_id", "occurred_at"]
        values = [
            None,
            "maintenance.restore",
            "database",
            destination.name[:64],
            datetime.now(UTC).isoformat(),
        ]
        if "details_json" in columns:
            fields.append("details_json")
            values.append(
                json.dumps({"backup_name": backup.name, "offline": True}, separators=(",", ":"))
            )
        placeholders = ", ".join("?" for _ in fields)
        column_list = ", ".join(fields)
        connection.execute(
            f"INSERT INTO audit_logs ({column_list}) VALUES ({placeholders})", values
        )
        connection.commit()
    finally:
        connection.close()


def restore(backup: Path, destination: Path, confirmed: bool) -> None:
    backup = backup.expanduser().resolve(strict=True)
    destination = destination.expanduser().resolve()
    if not confirmed:
        raise ValueError(
            "Pass --confirm-replace after stopping the API and verifying the target path"
        )
    if backup == destination:
        raise ValueError("Backup and destination must be different files")
    if destination.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
        raise ValueError("Destination must use a .db, .sqlite, or .sqlite3 extension")
    if destination.exists():
        with destination.open("rb") as existing:
            if existing.read(16) != b"SQLite format 3\x00":
                raise ValueError("Existing destination is not a SQLite database")
    verify_database(backup)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix="guardian-restore-", suffix=".sqlite3", dir=destination.parent
    )
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        source = sqlite3.connect(f"file:{backup.as_posix()}?mode=ro", uri=True)
        target = sqlite3.connect(temporary)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        verify_database(temporary)
        record_restore(temporary, backup, destination)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path, help="Verified .sqlite3 backup created by the API")
    parser.add_argument("destination", type=Path, help="SQLite database file to replace")
    parser.add_argument(
        "--confirm-replace", action="store_true", help="Confirm offline database replacement"
    )
    args = parser.parse_args()
    try:
        restore(args.backup, args.destination, args.confirm_replace)
    except (OSError, sqlite3.Error, ValueError) as error:
        parser.error(str(error))
    print(f"Restored verified database to {args.destination.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
