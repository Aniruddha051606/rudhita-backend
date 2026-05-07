-- ============================================================
-- migration_phase1.sql  –  Rudhita OMS Phase 1 Schema Upgrade
-- Run this ONCE on your PostgreSQL database on the Dell Optiplex.
-- Safe to re-run – all statements use IF NOT EXISTS / IF EXISTS.
-- ============================================================

-- ─────────────────────────────────────────────────────────────
-- 0. EXTENSIONS
-- ─────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS btree_gin;   -- needed for GIN on JSONB + btree

-- ─────────────────────────────────────────────────────────────
-- 1. ALTER EXISTING TABLES (additive only)
-- ─────────────────────────────────────────────────────────────

-- products: stock_quantity stays, but we flag it as a cache
COMMENT ON COLUMN products.stock_quantity IS
  'Legacy cache – mirrors InventoryLevel.available at primary location. '
  'Do NOT treat as source of truth.';

-- orders: new columns
ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS is_draft  BOOLEAN       NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS source    VARCHAR(50)   DEFAULT 'storefront',
    ADD COLUMN IF NOT EXISTS tags      JSONB         DEFAULT '[]'::jsonb;

-- GIN index on tags for fast @> and ? operator queries
CREATE INDEX IF NOT EXISTS ix_orders_tags_gin
    ON orders USING gin (tags);

-- Composite index for most common admin query pattern
CREATE INDEX IF NOT EXISTS ix_orders_payment_created
    ON orders (payment_status, created_at DESC);

-- order_items: no schema change needed (relationships handle it)

-- ─────────────────────────────────────────────────────────────
-- 2. NEW ENUM TYPES
-- ─────────────────────────────────────────────────────────────

DO $$ BEGIN
    CREATE TYPE location_type_enum AS ENUM ('warehouse','store','thirdparty');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE inventory_bucket_enum AS ENUM ('available','committed','unavailable');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE inventory_transaction_type_enum AS ENUM (
        'purchase_received','return_restocked','manual_adjustment_in',
        'order_committed','order_shipped','damage_write_off',
        'transfer_out','transfer_in','manual_adjustment_out','return_inspecting'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE fulfillment_status_enum AS ENUM
        ('pending','packed','shipped','delivered','failed','cancelled');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE return_status_enum AS ENUM (
        'requested','approved','rejected','received',
        'inspecting','restocked','refund_issued','closed'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE purchase_order_status_enum AS ENUM
        ('draft','sent','partial','received','cancelled');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ─────────────────────────────────────────────────────────────
-- 3. NEW TABLES
-- ─────────────────────────────────────────────────────────────

-- 3.1  locations
CREATE TABLE IF NOT EXISTS locations (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(150) NOT NULL UNIQUE,
    code            VARCHAR(20)  NOT NULL UNIQUE,
    location_type   location_type_enum NOT NULL DEFAULT 'warehouse',
    address         TEXT,
    city            VARCHAR(100),
    state           VARCHAR(100),
    pincode         VARCHAR(10),
    latitude        FLOAT,
    longitude       FLOAT,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_locations_code       ON locations (code);
CREATE INDEX IF NOT EXISTS ix_locations_city       ON locations (city);

-- Seed your primary warehouse – edit values as needed
INSERT INTO locations (name, code, location_type, city, state, pincode, is_active)
VALUES ('Main Warehouse', 'WH-MAIN-01', 'warehouse', 'Tiruchirappalli', 'Tamil Nadu', '620001', true)
ON CONFLICT (code) DO NOTHING;


-- 3.2  inventory_levels
CREATE TABLE IF NOT EXISTS inventory_levels (
    id          SERIAL PRIMARY KEY,
    product_id  INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    location_id INTEGER NOT NULL REFERENCES locations(id) ON DELETE CASCADE,
    available   INTEGER NOT NULL DEFAULT 0,
    committed   INTEGER NOT NULL DEFAULT 0,
    unavailable INTEGER NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_inventory_product_location UNIQUE (product_id, location_id)
);
CREATE INDEX IF NOT EXISTS ix_inventory_level_available
    ON inventory_levels (product_id, available);

-- Migrate existing stock quantities into inventory_levels
-- (runs for every product that doesn't already have an inventory_level row)
INSERT INTO inventory_levels (product_id, location_id, available)
SELECT p.id,
       (SELECT id FROM locations WHERE code = 'WH-MAIN-01' LIMIT 1),
       p.stock_quantity
FROM   products p
WHERE  NOT EXISTS (
    SELECT 1 FROM inventory_levels il
    WHERE il.product_id = p.id
      AND il.location_id = (SELECT id FROM locations WHERE code = 'WH-MAIN-01' LIMIT 1)
);


-- 3.3  inventory_transactions
CREATE TABLE IF NOT EXISTS inventory_transactions (
    id               SERIAL PRIMARY KEY,
    product_id       INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    location_id      INTEGER NOT NULL REFERENCES locations(id) ON DELETE CASCADE,
    transaction_type inventory_transaction_type_enum NOT NULL,
    bucket           inventory_bucket_enum NOT NULL,
    quantity_delta   INTEGER NOT NULL,
    reference_type   VARCHAR(50),
    reference_id     INTEGER,
    notes            TEXT,
    created_by       INTEGER REFERENCES users(id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_inv_txn_product_location_created
    ON inventory_transactions (product_id, location_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_inv_txn_reference
    ON inventory_transactions (reference_type, reference_id);
CREATE INDEX IF NOT EXISTS ix_inv_txn_type
    ON inventory_transactions (transaction_type);


-- 3.4  fulfillments
CREATE TABLE IF NOT EXISTS fulfillments (
    id              SERIAL PRIMARY KEY,
    order_id        INTEGER NOT NULL REFERENCES orders(id)    ON DELETE CASCADE,
    location_id     INTEGER          REFERENCES locations(id) ON DELETE SET NULL,
    status          fulfillment_status_enum NOT NULL DEFAULT 'pending',
    tracking_number VARCHAR(100),
    carrier         VARCHAR(100),
    tracking_url    VARCHAR(500),
    shipped_at      TIMESTAMPTZ,
    delivered_at    TIMESTAMPTZ,
    shipping_cost   NUMERIC(10,2) DEFAULT 0,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_fulfillments_order_id        ON fulfillments (order_id);
CREATE INDEX IF NOT EXISTS ix_fulfillments_status          ON fulfillments (status);
CREATE INDEX IF NOT EXISTS ix_fulfillments_tracking_number ON fulfillments (tracking_number);


-- 3.5  fulfillment_items
CREATE TABLE IF NOT EXISTS fulfillment_items (
    id             SERIAL PRIMARY KEY,
    fulfillment_id INTEGER NOT NULL REFERENCES fulfillments(id)  ON DELETE CASCADE,
    order_item_id  INTEGER NOT NULL REFERENCES order_items(id)   ON DELETE CASCADE,
    quantity       INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_fulfillment_items_fulfillment ON fulfillment_items (fulfillment_id);
CREATE INDEX IF NOT EXISTS ix_fulfillment_items_order_item  ON fulfillment_items (order_item_id);


-- 3.6  return_requests
CREATE TABLE IF NOT EXISTS return_requests (
    id                     SERIAL PRIMARY KEY,
    order_id               INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    user_id                INTEGER NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    status                 return_status_enum NOT NULL DEFAULT 'requested',
    reason                 VARCHAR(200),
    customer_note          TEXT,
    admin_note             TEXT,
    refund_amount          NUMERIC(10,2) DEFAULT 0,
    razorpay_refund_id     VARCHAR(100),
    return_tracking_number VARCHAR(100),
    return_carrier         VARCHAR(100),
    received_at            TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_return_requests_order_id ON return_requests (order_id);
CREATE INDEX IF NOT EXISTS ix_return_requests_user_id  ON return_requests (user_id);
CREATE INDEX IF NOT EXISTS ix_return_requests_status   ON return_requests (status);


-- 3.7  return_items
CREATE TABLE IF NOT EXISTS return_items (
    id                  SERIAL PRIMARY KEY,
    return_request_id   INTEGER NOT NULL REFERENCES return_requests(id) ON DELETE CASCADE,
    order_item_id       INTEGER NOT NULL REFERENCES order_items(id)     ON DELETE CASCADE,
    quantity_returned   INTEGER NOT NULL DEFAULT 1,
    condition           VARCHAR(50),
    restock             BOOLEAN NOT NULL DEFAULT true,
    refund_line_amount  NUMERIC(10,2) DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_return_items_return_request ON return_items (return_request_id);
CREATE INDEX IF NOT EXISTS ix_return_items_order_item     ON return_items (order_item_id);


-- 3.8  order_notes
CREATE TABLE IF NOT EXISTS order_notes (
    id                  SERIAL PRIMARY KEY,
    order_id            INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    author_id           INTEGER NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    body                TEXT NOT NULL,
    is_customer_visible BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_order_notes_order_id   ON order_notes (order_id, created_at DESC);


-- 3.9  purchase_orders
CREATE TABLE IF NOT EXISTS purchase_orders (
    id                      SERIAL PRIMARY KEY,
    po_number               VARCHAR(50) NOT NULL UNIQUE,
    destination_location_id INTEGER NOT NULL REFERENCES locations(id) ON DELETE RESTRICT,
    supplier_name           VARCHAR(200),
    supplier_contact        VARCHAR(150),
    status                  purchase_order_status_enum NOT NULL DEFAULT 'draft',
    expected_arrival        TIMESTAMPTZ,
    received_at             TIMESTAMPTZ,
    total_cost              NUMERIC(10,2) DEFAULT 0,
    notes                   TEXT,
    created_by              INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_purchase_orders_status     ON purchase_orders (status);
CREATE INDEX IF NOT EXISTS ix_purchase_orders_po_number  ON purchase_orders (po_number);


-- 3.10  purchase_order_items
CREATE TABLE IF NOT EXISTS purchase_order_items (
    id                SERIAL PRIMARY KEY,
    purchase_order_id INTEGER NOT NULL REFERENCES purchase_orders(id) ON DELETE CASCADE,
    product_id        INTEGER NOT NULL REFERENCES products(id)        ON DELETE RESTRICT,
    quantity_ordered  INTEGER NOT NULL DEFAULT 1,
    quantity_received INTEGER NOT NULL DEFAULT 0,
    cost_price        NUMERIC(10,2)
);
CREATE INDEX IF NOT EXISTS ix_poi_purchase_order ON purchase_order_items (purchase_order_id);
CREATE INDEX IF NOT EXISTS ix_poi_product        ON purchase_order_items (product_id);


-- ─────────────────────────────────────────────────────────────
-- 4. HELPER FUNCTION: apply_inventory_transaction()
-- ─────────────────────────────────────────────────────────────
-- Call this function instead of manually writing to both tables.
-- It writes the ledger row AND updates the cached bucket on inventory_levels
-- atomically inside the same transaction.

CREATE OR REPLACE FUNCTION apply_inventory_transaction(
    p_product_id        INTEGER,
    p_location_id       INTEGER,
    p_transaction_type  inventory_transaction_type_enum,
    p_bucket            inventory_bucket_enum,
    p_quantity_delta    INTEGER,
    p_reference_type    VARCHAR(50) DEFAULT NULL,
    p_reference_id      INTEGER     DEFAULT NULL,
    p_notes             TEXT        DEFAULT NULL,
    p_created_by        INTEGER     DEFAULT NULL
) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    -- 1. Insert the immutable ledger row
    INSERT INTO inventory_transactions
        (product_id, location_id, transaction_type, bucket,
         quantity_delta, reference_type, reference_id, notes, created_by)
    VALUES
        (p_product_id, p_location_id, p_transaction_type, p_bucket,
         p_quantity_delta, p_reference_type, p_reference_id, p_notes, p_created_by);

    -- 2. Upsert the cached inventory_level bucket
    INSERT INTO inventory_levels (product_id, location_id, available, committed, unavailable)
    VALUES (p_product_id, p_location_id, 0, 0, 0)
    ON CONFLICT (product_id, location_id) DO NOTHING;

    UPDATE inventory_levels SET
        available   = available   + CASE WHEN p_bucket = 'available'   THEN p_quantity_delta ELSE 0 END,
        committed   = committed   + CASE WHEN p_bucket = 'committed'   THEN p_quantity_delta ELSE 0 END,
        unavailable = unavailable + CASE WHEN p_bucket = 'unavailable' THEN p_quantity_delta ELSE 0 END,
        updated_at  = NOW()
    WHERE product_id  = p_product_id
      AND location_id = p_location_id;

    -- 3. Keep the legacy stock_quantity cache in sync
    UPDATE products
    SET stock_quantity = (
        SELECT COALESCE(SUM(available), 0)
        FROM   inventory_levels
        WHERE  product_id = p_product_id
    )
    WHERE id = p_product_id;
END;
$$;

-- Example usage:
-- SELECT apply_inventory_transaction(
--     42, 1, 'order_committed', 'available', -2,
--     'order', 1001, 'Customer checkout'
-- );
-- SELECT apply_inventory_transaction(
--     42, 1, 'order_committed', 'committed', +2,
--     'order', 1001, 'Customer checkout'
-- );
