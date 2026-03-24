from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import get_settings

settings = get_settings()


def normalize_database_url(database_url: str) -> str:
    value = str(database_url or "").strip()
    if not value:
        return value

    lowered = value.lower()
    if lowered.startswith("sqlite"):
        return value

    url = make_url(value)
    if url.drivername in {"postgres", "postgresql"}:
        url = url.set(drivername="postgresql+psycopg")
    return url.render_as_string(hide_password=False)


def describe_database_target(database_url: str) -> str:
    value = str(database_url or "").strip()
    if not value:
        return "unknown"

    try:
        url: URL = make_url(value)
    except Exception:
        return "invalid"

    if url.drivername.startswith("sqlite"):
        return f"{url.drivername}:///{url.database or ''}"

    host = url.host or "unknown-host"
    database_name = url.database or "unknown-db"
    return f"{url.drivername}://{host}/{database_name}"


resolved_database_url = normalize_database_url(settings.database_url)
connect_args = {}
engine_kwargs = {
    "pool_pre_ping": True,
}
if resolved_database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    connect_args = {"connect_timeout": 10}
    engine_kwargs.update(
        pool_recycle=300,
        pool_use_lifo=True,
    )

engine = create_engine(
    resolved_database_url,
    connect_args=connect_args,
    **engine_kwargs,
)
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)
database_backend = engine.dialect.name
database_target = describe_database_target(resolved_database_url)

Base = declarative_base()


def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
