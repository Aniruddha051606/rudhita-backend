import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import QueuePool
from dotenv import load_dotenv

load_dotenv()

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

if not SQLALCHEMY_DATABASE_URL:
    raise ValueError(
        "DATABASE_URL is not set. "
        "Add it to your .env file: DATABASE_URL=postgresql://user:pass@host/dbname"
    )

# ── High-performance connection pool ────────────────────────────────────────
# pool_size=10      → 10 persistent connections kept alive at all times
# max_overflow=20   → up to 20 extra connections under burst traffic
# pool_pre_ping=True → validates connections before use (handles stale TCP)
# pool_recycle=1800  → recycles connections every 30 min (prevents timeouts)
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    poolclass=QueuePool,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=1800,
    connect_args={"options": "-c timezone=utc"},
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    # expire_on_commit=False → objects stay usable after commit without
    # a second round-trip to the DB to re-fetch them
    expire_on_commit=False,
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()