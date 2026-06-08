from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker


BACKEND_ROOT = Path(__file__).parents[1]
DEFAULT_DATABASE = BACKEND_ROOT / "data" / "vms.db"
DATABASE_URL = os.getenv("VMS_DATABASE_URL", f"sqlite:///{DEFAULT_DATABASE.as_posix()}")

if DATABASE_URL.startswith("sqlite:///"):
    Path(DATABASE_URL.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def ensure_sqlite_schema() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        return
    inspector = inspect(engine)
    if "vulnerability_records" not in inspector.get_table_names():
        return
    existing_columns = {column["name"] for column in inspector.get_columns("vulnerability_records")}
    required_columns = {
        "is_deleted": "ALTER TABLE vulnerability_records ADD COLUMN is_deleted BOOLEAN DEFAULT 0",
        "deleted_at": "ALTER TABLE vulnerability_records ADD COLUMN deleted_at DATETIME",
        "deleted_by": "ALTER TABLE vulnerability_records ADD COLUMN deleted_by VARCHAR(100) DEFAULT ''",
        "deleted_reason": "ALTER TABLE vulnerability_records ADD COLUMN deleted_reason TEXT DEFAULT ''",
    }
    with engine.begin() as connection:
        for column_name, ddl in required_columns.items():
            if column_name not in existing_columns:
                connection.execute(text(ddl))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
