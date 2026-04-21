-- ════════════════════════════════════════════════════════════════
-- migration_001_audit_fixes.sql
--
-- Run this ONCE on your existing PostgreSQL database before
-- deploying the patched Python code.
--
-- Safe to run on a live DB — all statements use IF EXISTS / IF NOT EXISTS.
-- Recommended: take a pg_dump backup first.
-- ════════════════════════════════════════════════════════════════

BEGIN;

-- ── 1. Fix money columns: Float → NUMERIC(10,2) ───────────────────────────
--    Prevents floating-point drift on prices and order totals.

ALTER TABLE products
    ALTER COLUMN price          TYPE NUMERIC(10, 2) USING price::NUMERIC(10, 2),
    ALTER COLUMN original_price TYPE NUMERIC(10, 2) USING original_price::NUMERIC(10, 2);

ALTER TABLE orders
    ALTER COLUMN total_amount TYPE NUMERIC(10, 2) USING total_amount::NUMERIC(10, 2);

ALTER TABLE order_items
    ALTER COLUMN price_at_purchase TYPE NUMERIC(10, 2) USING price_at_purchase::NUMERIC(10, 2);

-- ── 2. Fix is_verified: Integer → Boolean ────────────────────────────────
ALTER TABLE users
    ALTER COLUMN is_verified TYPE BOOLEAN USING (is_verified::int::boolean);

-- ── 3. Make password_hash NOT NULL (only if all rows already have a hash) ──
--    Uncomment after verifying: SELECT COUNT(*) FROM users WHERE password_hash IS NULL;
-- ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL;

-- ── 4. Widen OTP hash column to hold SHA-256 hex (64 chars) ──────────────
ALTER TABLE otps
    ALTER COLUMN otp_code TYPE VARCHAR(64);

-- ── 5. Create refresh_tokens table ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token      VARCHAR(128) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_token   ON refresh_tokens(token);

-- ── 6. Create token_blocklist table ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS token_blocklist (
    id         SERIAL PRIMARY KEY,
    jti        VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_token_blocklist_jti        ON token_blocklist(jti);
CREATE INDEX IF NOT EXISTS ix_token_blocklist_expires_at ON token_blocklist(expires_at);

-- ── 7. Create audit_logs table ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id          SERIAL PRIMARY KEY,
    actor_id    INTEGER NOT NULL REFERENCES users(id),
    action      VARCHAR(100) NOT NULL,
    target_type VARCHAR(50),
    target_id   INTEGER,
    detail      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_audit_logs_actor_id   ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_created_at ON audit_logs(created_at);

-- ── 8. Cleanup job: delete expired blocklist entries ─────────────────────
--    Add this as a daily cron or pg_cron job:
-- DELETE FROM token_blocklist WHERE expires_at < NOW();
-- DELETE FROM refresh_tokens  WHERE expires_at < NOW();

COMMIT;

-- ── Verify ────────────────────────────────────────────────────────────────
SELECT
    table_name,
    column_name,
    data_type
FROM information_schema.columns
WHERE table_name IN ('products','orders','order_items','users','otps')
  AND column_name IN ('price','original_price','total_amount','price_at_purchase','is_verified','otp_code')
ORDER BY table_name, column_name;
