-- migration_phase3.sql -- Rudhita Phase 3 (Google OAuth, Reviews, Wishlist)
-- Run: psql -h 127.0.0.1 -U rudhita_admin -d rudhita_db -f migration_phase3.sql

ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(20)  NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id     VARCHAR(128);
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url    VARCHAR(500);
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ix_users_google_id ON users (google_id) WHERE google_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS product_reviews (
    id          SERIAL PRIMARY KEY,
    product_id  INTEGER  NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    user_id     INTEGER  NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    rating      SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
    title       VARCHAR(200),
    body        TEXT,
    is_verified BOOLEAN  NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_review_user_product UNIQUE (user_id, product_id)
);
CREATE INDEX IF NOT EXISTS ix_reviews_product ON product_reviews (product_id, created_at DESC);

CREATE TABLE IF NOT EXISTS wishlist_items (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_wishlist_user_product UNIQUE (user_id, product_id)
);
CREATE INDEX IF NOT EXISTS ix_wishlist_user ON wishlist_items (user_id);

SELECT 'migration_phase3 complete' AS status;
