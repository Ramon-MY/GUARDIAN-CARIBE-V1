from collections.abc import Generator

from sqlalchemy import Column, DateTime, Integer, Table, create_engine, func, inspect, select
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from guardian_caribe.config import get_settings


class Base(DeclarativeBase):
    pass


schema_migrations = Table(
    "schema_migrations",
    Base.metadata,
    Column("version", Integer, primary_key=True),
    Column("applied_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)


def _build_engine():
    url = get_settings().database_url
    kwargs = {"check_same_thread": False} if url.startswith("sqlite:") else {}
    return create_engine(url, connect_args=kwargs, pool_pre_ping=True)


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def upgrade_schema() -> None:
    """Create current tables and apply idempotent, versioned additions to older prototypes."""
    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        current = connection.execute(select(func.max(schema_migrations.c.version))).scalar_one()
        current = current or 0
        if current < 1:
            columns = {
                table: {column["name"] for column in inspect(connection).get_columns(table)}
                for table in ("security_events", "audit_logs")
            }
            if "url" not in columns["security_events"]:
                connection.exec_driver_sql(
                    "ALTER TABLE security_events ADD COLUMN url VARCHAR(2048)"
                )
            if "details_json" not in columns["audit_logs"]:
                connection.exec_driver_sql(
                    "ALTER TABLE audit_logs ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}'"
                )
            connection.execute(schema_migrations.insert().values(version=1))
            current = 1
        if current < 2:
            connection.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_security_events_url ON security_events (url)"
            )
            if connection.dialect.name == "postgresql":
                connection.exec_driver_sql(
                    "ALTER TABLE indicators ALTER COLUMN value TYPE VARCHAR(2048)"
                )
            connection.execute(schema_migrations.insert().values(version=2))
