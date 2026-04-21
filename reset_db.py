"""
reset_db.py  —  Database Reset Utility (PATCHED)

Changes from audit:
  - Hard blocks execution in production (ENV=production)
  - Requires typing RESET to confirm — no accidental wipes
  - Logs a warning before proceeding
"""

import os
import logging

logger = logging.getLogger("rudhita")

# ── SAFETY GUARD ─────────────────────────────────────────────────────────────
if os.getenv("ENV", "development").lower() == "production":
    raise SystemExit(
        "\n"
        "  ╔══════════════════════════════════════════════════════╗\n"
        "  ║  reset_db.py is DISABLED in production.              ║\n"
        "  ║  This script drops every table and all user data.    ║\n"
        "  ║  Use Alembic migrations for schema changes in prod.  ║\n"
        "  ╚══════════════════════════════════════════════════════╝\n"
    )

confirm = input(
    "\n⚠️  WARNING: This will DROP every table and delete ALL data.\n"
    "   Type RESET to confirm, or anything else to abort: "
)
if confirm.strip() != "RESET":
    raise SystemExit("Aborted — no changes made.")

second = input("   Are you absolutely sure? Type YES to proceed: ")
if second.strip() != "YES":
    raise SystemExit("Aborted — no changes made.")

# ── Only reaches here in development after double confirmation ────────────────
import models
from database import engine
from sqlalchemy import text

print("\nDropping all tables...")
with engine.connect() as conn:
    conn.execute(text("DROP SCHEMA public CASCADE;"))
    conn.execute(text("CREATE SCHEMA public;"))
    conn.execute(text("GRANT ALL ON SCHEMA public TO postgres;"))
    conn.execute(text("GRANT ALL ON SCHEMA public TO public;"))
    conn.execute(text("GRANT ALL ON SCHEMA public TO rudhita_admin;"))
    conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO rudhita_admin;"))
    conn.execute(text("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO rudhita_admin;"))
    conn.commit()

print("Rebuilding schema from models.py...")
models.Base.metadata.create_all(bind=engine)

print("\n✅ Done. Tables created:")
with engine.connect() as conn:
    result = conn.execute(text(
        "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
    ))
    for row in result:
        print(f"  • {row[0]}")
