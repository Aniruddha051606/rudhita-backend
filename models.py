"""
models.py  – Rudhita OMS  |  PHASE 1: Enterprise Schema Redesign
=================================================================

UPGRADE SUMMARY (vs previous version)
---------------------------------------
NEW MODELS
  Location             – Physical warehouse / store locations with coordinates
                         for geospatial routing via the Haversine formula.
  InventoryLevel       – Per-product, per-location stock split into three
                         buckets: available / committed / unavailable.
  InventoryTransaction – Immutable ledger rows. Inventory is NEVER mutated
                         by editing a single integer; it is always derived
                         by summing this ledger.
  Fulfillment          – Represents one physical shipment for an Order.
                         An Order can have many Fulfillments (split/partial).
  FulfillmentItem      – Which OrderItems (and how many units) are packed
                         into a given Fulfillment.
  ReturnRequest        – Customer return, linked back to specific OrderItems.
  ReturnItem           – Granular per-line-item detail inside a return.
  OrderNote            – Admin timeline notes / comments on an Order.
  PurchaseOrder        – Supplier purchase order for restocking.
  PurchaseOrderItem    – Line items inside a Purchase Order.

MODIFIED MODELS
  Product  – Added `inventory_levels` and `inventory_transactions`
             relationships. `stock_quantity` is kept as a *cached / derived*
             column for backward-compatibility with existing admin routes –
             it should be refreshed whenever the ledger changes (see note).
  Order    – Added `tags` (JSONB), `notes`, `fulfillments`, `return_requests`,
             `is_draft`, and `source` fields.
  OrderItem– Added `fulfillment_items` and `return_items` back-refs.
  User     – Added `return_requests` relationship.

MIGRATION NOTE (run after deploying this file)
  See migration_phase1.sql for the ALTER TABLE and CREATE TABLE statements.
  The short version:
    ALTER TABLE products ADD COLUMN IF NOT EXISTS stock_quantity_cache INTEGER DEFAULT 0;
    ALTER TABLE orders   ADD COLUMN IF NOT EXISTS tags    JSONB DEFAULT '[]';
    ALTER TABLE orders   ADD COLUMN IF NOT EXISTS is_draft BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE orders   ADD COLUMN IF NOT EXISTS source  VARCHAR(50) DEFAULT 'storefront';
    -- then CREATE TABLE for all new tables below

DOUBLE-ENTRY INVENTORY LEDGER – HOW IT WORKS
=============================================
The core idea mirrors double-entry bookkeeping:

  1. `InventoryLevel` holds THREE live-aggregate buckets per (product, location):
       • available    – can be sold right now
       • committed    – reserved by an unpaid / unshipped order
       • unavailable  – damaged, quarantined, or under return inspection

  2. Every stock movement writes ONE row to `InventoryTransaction` with:
       • transaction_type  – e.g. "purchase_received", "order_committed",
                             "order_shipped", "return_restocked", "damage_write_off"
       • quantity_delta    – signed integer (+/-)
       • bucket            – which of the three buckets is affected

  3. The ground-truth available stock = SUM(quantity_delta)
     WHERE bucket = 'available' AND product_id = X AND location_id = Y

  4. `InventoryLevel.available` is a *denormalised cache* – updated
     atomically with each transaction write (same DB session).  This means
     reads are O(1) while the ledger provides an infinite audit trail.

  Example flow for a customer placing an order for 2 units:
    ┌──────────────────────────────────────────────────────────────────────┐
    │ TRANSACTION 1 – checkout                                             │
    │   type:  "order_committed"    delta: -2  bucket: available           │
    │   type:  "order_committed"    delta: +2  bucket: committed           │
    │ → InventoryLevel.available -= 2                                      │
    │ → InventoryLevel.committed += 2                                      │
    ├──────────────────────────────────────────────────────────────────────┤
    │ TRANSACTION 2 – fulfillment / shipment                               │
    │   type:  "order_shipped"      delta: -2  bucket: committed           │
    │ → InventoryLevel.committed -= 2  (item is now in the courier's hands)│
    ├──────────────────────────────────────────────────────────────────────┤
    │ TRANSACTION 3 – customer return accepted                             │
    │   type:  "return_inspecting"  delta: +2  bucket: unavailable         │
    │ After QC passes:                                                      │
    │   type:  "return_restocked"   delta: -2  bucket: unavailable         │
    │   type:  "return_restocked"   delta: +2  bucket: available           │
    └──────────────────────────────────────────────────────────────────────┘
"""

from sqlalchemy import (
    Column, Integer, String, Float, ForeignKey,
    DateTime, Text, Boolean, Index, Numeric, Enum,
    UniqueConstraint, SmallInteger
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base

import enum


# ─────────────────────────────────────────────────────────────────────────────
# ENUMERATIONS
# ─────────────────────────────────────────────────────────────────────────────

class LocationType(str, enum.Enum):
    warehouse = "warehouse"
    store     = "store"
    thirdparty = "thirdparty"          # 3PL


class InventoryBucket(str, enum.Enum):
    available   = "available"
    committed   = "committed"          # in an order, not yet shipped
    unavailable = "unavailable"        # damaged / under inspection


class InventoryTransactionType(str, enum.Enum):
    # Inbound
    purchase_received    = "purchase_received"    # PO goods arrived
    return_restocked     = "return_restocked"      # return passed QC → back to shelf
    manual_adjustment_in = "manual_adjustment_in"  # stock-take correction (positive)
    # Outbound / internal
    order_committed      = "order_committed"       # cart checkout → reserved
    order_shipped        = "order_shipped"         # handed to courier
    damage_write_off     = "damage_write_off"      # irreparably damaged
    transfer_out         = "transfer_out"          # moved to another location
    transfer_in          = "transfer_in"           # received from another location
    manual_adjustment_out = "manual_adjustment_out" # stock-take correction (negative)
    # Return pipeline
    return_inspecting    = "return_inspecting"     # goods received from customer


class FulfillmentStatus(str, enum.Enum):
    pending   = "pending"
    packed    = "packed"
    shipped   = "shipped"
    delivered = "delivered"
    failed    = "failed"
    cancelled = "cancelled"


class ReturnStatus(str, enum.Enum):
    requested   = "requested"
    approved    = "approved"
    rejected    = "rejected"
    received    = "received"           # physical parcel back in warehouse
    inspecting  = "inspecting"
    restocked   = "restocked"
    refund_issued = "refund_issued"
    closed      = "closed"


class PurchaseOrderStatus(str, enum.Enum):
    draft     = "draft"
    sent      = "sent"
    partial   = "partial"              # some items received
    received  = "received"             # all items received
    cancelled = "cancelled"


# ─────────────────────────────────────────────────────────────────────────────
# EXISTING MODELS  (backward-compatible, with additive changes only)
# ─────────────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"
    id             = Column(Integer, primary_key=True, index=True)
    name           = Column(String(100), nullable=False)
    email          = Column(String(150), unique=True, nullable=False, index=True)
    password_hash  = Column(String(255), nullable=False)
    phone          = Column(String(20))
    is_verified    = Column(Boolean, default=False, nullable=False)
    is_admin       = Column(Boolean, default=False)
    created_at     = Column(DateTime(timezone=True), server_default=func.now())

    orders          = relationship("Order",         back_populates="owner",   lazy="select")
    cart            = relationship("Cart",          back_populates="user",    uselist=False)
    addresses       = relationship("Address",       back_populates="user",    cascade="all, delete-orphan")
    refresh_tokens  = relationship("RefreshToken",  back_populates="user",    cascade="all, delete-orphan")
    return_requests = relationship("ReturnRequest", back_populates="customer", lazy="select")  # NEW


class Address(Base):
    __tablename__ = "addresses"
    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name       = Column(String(150), nullable=False)
    phone      = Column(String(20),  nullable=False)
    street     = Column(Text, nullable=False)
    city       = Column(String(100), nullable=False)
    state      = Column(String(100), nullable=False)
    pincode    = Column(String(10),  nullable=False)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user       = relationship("User", back_populates="addresses")


class Product(Base):
    """
    stock_quantity is kept as a CACHED COLUMN for legacy admin routes.
    It should mirror InventoryLevel.available at the primary warehouse.
    Do NOT trust it as the source of truth – always query InventoryLevel.
    """
    __tablename__ = "products"
    id             = Column(Integer, primary_key=True, index=True)
    sku            = Column(String(50), unique=True, nullable=False, index=True)
    name           = Column(String(200), nullable=False)
    description    = Column(Text)
    category       = Column(String(100), index=True)
    price          = Column(Numeric(10, 2), nullable=False)
    original_price = Column(Numeric(10, 2))
    stock_quantity = Column(Integer, default=0, nullable=False)   # LEGACY CACHE – see note
    weight_grams   = Column(Integer, default=0, nullable=False)
    image_url      = Column(String(500))
    is_active      = Column(Boolean, default=True)
    created_at     = Column(DateTime(timezone=True), server_default=func.now())

    inventory_levels       = relationship("InventoryLevel",       back_populates="product",  lazy="select")  # NEW
    inventory_transactions = relationship("InventoryTransaction", back_populates="product",  lazy="select")  # NEW

    __table_args__ = (Index("ix_products_category_price", "category", "price"),)


class Order(Base):
    __tablename__ = "orders"
    id                  = Column(Integer, primary_key=True, index=True)
    user_id             = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    total_amount        = Column(Numeric(10, 2), nullable=False)
    payment_status      = Column(String(50), default="Pending",  index=True)
    shipping_status     = Column(String(50), default="Pending",  index=True)
    razorpay_order_id   = Column(String(100), index=True)
    razorpay_payment_id = Column(String(100))
    razorpay_refund_id  = Column(String(100))
    delhivery_waybill   = Column(String(100), index=True)
    shipping_address    = Column(Text, nullable=False)
    created_at          = Column(DateTime(timezone=True), server_default=func.now())
    updated_at          = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # ── NEW fields ──────────────────────────────────────────────────────────
    is_draft  = Column(Boolean, default=False, nullable=False)
    # Source tells you where the order originated: 'storefront' | 'admin_draft' | 'pos'
    source    = Column(String(50), default="storefront")
    # Free-form tags for admin filtering, e.g. ["VIP", "fragile", "express"]
    tags      = Column(JSONB, default=list)
    # ────────────────────────────────────────────────────────────────────────

    owner           = relationship("User",          back_populates="orders")
    items           = relationship("OrderItem",     back_populates="order",     cascade="all, delete-orphan")
    tracking_events = relationship(
        "TrackingEvent", back_populates="order",
        order_by="TrackingEvent.created_at",        cascade="all, delete-orphan"
    )
    fulfillments    = relationship("Fulfillment",   back_populates="order",     cascade="all, delete-orphan")  # NEW
    return_requests = relationship("ReturnRequest", back_populates="order",     cascade="all, delete-orphan")  # NEW
    notes           = relationship(                                                                              # NEW
        "OrderNote", back_populates="order",
        order_by="OrderNote.created_at",            cascade="all, delete-orphan"
    )

    __table_args__ = (
        # GIN index on JSONB tags column – enables fast @> / ? queries
        Index("ix_orders_tags_gin", tags, postgresql_using="gin"),
        # Composite index for the most common admin filter combo
        Index("ix_orders_payment_created", "payment_status", "created_at"),
    )


class OrderItem(Base):
    __tablename__ = "order_items"
    id                = Column(Integer, primary_key=True, index=True)
    order_id          = Column(Integer, ForeignKey("orders.id"),   nullable=False, index=True)
    product_id        = Column(Integer, ForeignKey("products.id"), nullable=False)
    quantity          = Column(Integer, nullable=False, default=1)
    price_at_purchase = Column(Numeric(10, 2), nullable=False)

    order            = relationship("Order",           back_populates="items")
    product          = relationship("Product")
    fulfillment_items = relationship("FulfillmentItem", back_populates="order_item")  # NEW
    return_items     = relationship("ReturnItem",       back_populates="order_item")  # NEW


class TrackingEvent(Base):
    __tablename__ = "tracking_events"
    id          = Column(Integer, primary_key=True, index=True)
    order_id    = Column(Integer, ForeignKey("orders.id"), nullable=False, index=True)
    status      = Column(String(100), nullable=False)
    location    = Column(String(200))
    description = Column(Text)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())
    order       = relationship("Order", back_populates="tracking_events")


class OTP(Base):
    __tablename__ = "otps"
    id         = Column(Integer, primary_key=True, index=True)
    email      = Column(String(150), nullable=False, index=True)
    otp_code   = Column(String(64),  nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    fail_count = Column(Integer, nullable=False, default=0)


class Cart(Base):
    __tablename__ = "carts"
    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user  = relationship("User",     back_populates="cart")
    items = relationship("CartItem", back_populates="cart", cascade="all, delete-orphan")


class CartItem(Base):
    __tablename__ = "cart_items"
    id         = Column(Integer, primary_key=True, index=True)
    cart_id    = Column(Integer, ForeignKey("carts.id"),    nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    quantity   = Column(Integer, default=1, nullable=False)
    cart    = relationship("Cart",    back_populates="items")
    product = relationship("Product")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token      = Column(String(128), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user       = relationship("User", back_populates="refresh_tokens")


class TokenBlocklist(Base):
    __tablename__ = "token_blocklist"
    id         = Column(Integer, primary_key=True, index=True)
    jti        = Column(String(64), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id          = Column(Integer, primary_key=True, index=True)
    actor_id    = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    action      = Column(String(100), nullable=False)
    target_type = Column(String(50))
    target_id   = Column(Integer)
    detail      = Column(Text)
    created_at  = Column(DateTime(timezone=True), server_default=func.now(), index=True)


# ─────────────────────────────────────────────────────────────────────────────
# NEW MODEL 1: LOCATION
# ─────────────────────────────────────────────────────────────────────────────

class Location(Base):
    """
    A physical place where inventory can live: warehouse, store, or 3PL.

    latitude / longitude are used by the Haversine smart-routing algorithm
    to find the nearest fulfillment location for a given customer pincode.
    """
    __tablename__ = "locations"
    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(150), nullable=False, unique=True)
    code        = Column(String(20),  nullable=False, unique=True, index=True)  # e.g. "WH-CHENNAI-01"
    location_type = Column(
        Enum(LocationType, name="location_type_enum"), nullable=False,
        default=LocationType.warehouse
    )
    address     = Column(Text)
    city        = Column(String(100), index=True)
    state       = Column(String(100))
    pincode     = Column(String(10))
    latitude    = Column(Float)          # for Haversine routing
    longitude   = Column(Float)
    is_active   = Column(Boolean, default=True)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())

    inventory_levels       = relationship("InventoryLevel",       back_populates="location")
    inventory_transactions = relationship("InventoryTransaction", back_populates="location")
    fulfillments           = relationship("Fulfillment",          back_populates="location")
    purchase_orders        = relationship("PurchaseOrder",        back_populates="destination_location")


# ─────────────────────────────────────────────────────────────────────────────
# NEW MODEL 2: INVENTORY LEVEL
# ─────────────────────────────────────────────────────────────────────────────

class InventoryLevel(Base):
    """
    Denormalised stock-count cache per (product, location).

    These three columns are ALWAYS updated together with every
    InventoryTransaction write in the same DB session.

    The three buckets:
      available   – units that can be sold right now
      committed   – reserved by placed but unshipped orders
      unavailable – damaged, under QC, or quarantined

    total_on_hand = available + committed + unavailable
    """
    __tablename__ = "inventory_levels"
    id          = Column(Integer, primary_key=True, index=True)
    product_id  = Column(Integer, ForeignKey("products.id"),  nullable=False, index=True)
    location_id = Column(Integer, ForeignKey("locations.id"), nullable=False, index=True)
    available   = Column(Integer, default=0, nullable=False)
    committed   = Column(Integer, default=0, nullable=False)
    unavailable = Column(Integer, default=0, nullable=False)
    updated_at  = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    product  = relationship("Product",  back_populates="inventory_levels")
    location = relationship("Location", back_populates="inventory_levels")

    __table_args__ = (
        UniqueConstraint("product_id", "location_id", name="uq_inventory_product_location"),
        Index("ix_inventory_level_available", "product_id", "available"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# NEW MODEL 3: INVENTORY TRANSACTION (THE LEDGER)
# ─────────────────────────────────────────────────────────────────────────────

class InventoryTransaction(Base):
    """
    Immutable ledger of every inventory movement. Never delete rows.

    quantity_delta is SIGNED:
      +N  →  stock increases in this bucket
      -N  →  stock decreases in this bucket

    A single real-world event (e.g. checkout) may produce TWO rows:
      row 1: bucket=available,  delta=-2   (removed from available)
      row 2: bucket=committed,  delta=+2   (added to committed)
    """
    __tablename__ = "inventory_transactions"
    id               = Column(Integer, primary_key=True, index=True)
    product_id       = Column(Integer, ForeignKey("products.id"),  nullable=False, index=True)
    location_id      = Column(Integer, ForeignKey("locations.id"), nullable=False, index=True)
    transaction_type = Column(
        Enum(InventoryTransactionType, name="inventory_transaction_type_enum"),
        nullable=False, index=True
    )
    bucket           = Column(
        Enum(InventoryBucket, name="inventory_bucket_enum"),
        nullable=False
    )
    quantity_delta   = Column(Integer, nullable=False)   # signed – positive = in, negative = out
    reference_type   = Column(String(50))                # "order" | "return" | "purchase_order" | "manual"
    reference_id     = Column(Integer, index=True)       # FK to the related entity (Order.id, etc.)
    notes            = Column(Text)
    created_by       = Column(Integer, ForeignKey("users.id"))
    created_at       = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    product  = relationship("Product",  back_populates="inventory_transactions")
    location = relationship("Location", back_populates="inventory_transactions")
    actor    = relationship("User",     foreign_keys=[created_by])

    __table_args__ = (
        Index("ix_inv_txn_product_location_created", "product_id", "location_id", "created_at"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# NEW MODEL 4: FULFILLMENT  (Order → physical shipment separation)
# ─────────────────────────────────────────────────────────────────────────────

class Fulfillment(Base):
    """
    One physical shipment.  An Order can have 1..N Fulfillments:
      - Normal:  1 fulfillment for the whole order
      - Split:   2 fulfillments (e.g. one item out of stock, rest ships today)
      - Partial: fulfillment created only for the in-stock subset

    `location_id` records which warehouse this fulfillment was picked from.
    """
    __tablename__ = "fulfillments"
    id               = Column(Integer, primary_key=True, index=True)
    order_id         = Column(Integer, ForeignKey("orders.id"),    nullable=False, index=True)
    location_id      = Column(Integer, ForeignKey("locations.id"), nullable=True,  index=True)
    status           = Column(
        Enum(FulfillmentStatus, name="fulfillment_status_enum"),
        default=FulfillmentStatus.pending, nullable=False, index=True
    )
    tracking_number  = Column(String(100), index=True)
    carrier          = Column(String(100))                # "Delhivery", "BlueDart", etc.
    tracking_url     = Column(String(500))
    shipped_at       = Column(DateTime(timezone=True))
    delivered_at     = Column(DateTime(timezone=True))
    shipping_cost    = Column(Numeric(10, 2), default=0)
    # Admin notes specific to this shipment
    notes            = Column(Text)
    created_at       = Column(DateTime(timezone=True), server_default=func.now())
    updated_at       = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    order    = relationship("Order",           back_populates="fulfillments")
    location = relationship("Location",        back_populates="fulfillments")
    items    = relationship("FulfillmentItem", back_populates="fulfillment", cascade="all, delete-orphan")


class FulfillmentItem(Base):
    """
    Tracks which OrderItems (and how many units) went into a Fulfillment.
    Needed for partial / split shipments where not all items go at once.
    """
    __tablename__ = "fulfillment_items"
    id              = Column(Integer, primary_key=True, index=True)
    fulfillment_id  = Column(Integer, ForeignKey("fulfillments.id"),  nullable=False, index=True)
    order_item_id   = Column(Integer, ForeignKey("order_items.id"),   nullable=False, index=True)
    quantity        = Column(Integer, nullable=False, default=1)

    fulfillment = relationship("Fulfillment", back_populates="items")
    order_item  = relationship("OrderItem",   back_populates="fulfillment_items")


# ─────────────────────────────────────────────────────────────────────────────
# NEW MODEL 5: RETURN REQUEST
# ─────────────────────────────────────────────────────────────────────────────

class ReturnRequest(Base):
    """
    A customer return. Linked to the originating Order and specific
    ReturnItems (which OrderItem lines are being returned).

    The refund_amount is the calculated refund total; it can be
    less than the original amount (e.g. restocking fee, partial return).
    """
    __tablename__ = "return_requests"
    id            = Column(Integer, primary_key=True, index=True)
    order_id      = Column(Integer, ForeignKey("orders.id"), nullable=False, index=True)
    user_id       = Column(Integer, ForeignKey("users.id"),  nullable=False, index=True)
    status        = Column(
        Enum(ReturnStatus, name="return_status_enum"),
        default=ReturnStatus.requested, nullable=False, index=True
    )
    reason        = Column(String(200))      # "damaged", "wrong_item", "changed_mind", etc.
    customer_note = Column(Text)             # Customer's free-text explanation
    admin_note    = Column(Text)             # Internal admin comments
    refund_amount = Column(Numeric(10, 2), default=0)
    razorpay_refund_id = Column(String(100))
    # Return shipment info (customer ships back to us)
    return_tracking_number = Column(String(100))
    return_carrier         = Column(String(100))
    received_at            = Column(DateTime(timezone=True))
    created_at             = Column(DateTime(timezone=True), server_default=func.now())
    updated_at             = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    order    = relationship("Order", back_populates="return_requests")
    customer = relationship("User",  back_populates="return_requests")
    items    = relationship("ReturnItem", back_populates="return_request", cascade="all, delete-orphan")


class ReturnItem(Base):
    """
    One line in a ReturnRequest.
    `restock` controls whether passed-QC units go back to inventory.
    """
    __tablename__ = "return_items"
    id                = Column(Integer, primary_key=True, index=True)
    return_request_id = Column(Integer, ForeignKey("return_requests.id"), nullable=False, index=True)
    order_item_id     = Column(Integer, ForeignKey("order_items.id"),     nullable=False, index=True)
    quantity_returned = Column(Integer, nullable=False, default=1)
    condition         = Column(String(50))    # "new", "good", "damaged", "unsellable"
    restock           = Column(Boolean, default=True)  # Should QC-passed units be restocked?
    refund_line_amount = Column(Numeric(10, 2), default=0)

    return_request = relationship("ReturnRequest", back_populates="items")
    order_item     = relationship("OrderItem",     back_populates="return_items")


# ─────────────────────────────────────────────────────────────────────────────
# NEW MODEL 6: ORDER NOTE  (Admin timeline)
# ─────────────────────────────────────────────────────────────────────────────

class OrderNote(Base):
    """
    An admin-visible timeline comment on an Order.
    `is_customer_visible` controls whether it shows up in the customer's
    order-status page (e.g. "Your order has been prioritised" vs
    internal "customer called twice, escalate").
    """
    __tablename__ = "order_notes"
    id                  = Column(Integer, primary_key=True, index=True)
    order_id            = Column(Integer, ForeignKey("orders.id"), nullable=False, index=True)
    author_id           = Column(Integer, ForeignKey("users.id"),  nullable=False)
    body                = Column(Text, nullable=False)
    is_customer_visible = Column(Boolean, default=False)
    created_at          = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    order  = relationship("Order", back_populates="notes")
    author = relationship("User",  foreign_keys=[author_id])


# ─────────────────────────────────────────────────────────────────────────────
# NEW MODEL 7: PURCHASE ORDER  (Restock from supplier)
# ─────────────────────────────────────────────────────────────────────────────

class PurchaseOrder(Base):
    """
    A purchase order sent to a supplier.
    When `status` transitions to 'received', a background task should:
      1. Create InventoryTransaction rows (type=purchase_received, bucket=available)
      2. Update InventoryLevel.available for each item
      3. Update Product.stock_quantity cache
    """
    __tablename__ = "purchase_orders"
    id                   = Column(Integer, primary_key=True, index=True)
    po_number            = Column(String(50), unique=True, nullable=False, index=True)  # e.g. "PO-2025-0041"
    destination_location_id = Column(Integer, ForeignKey("locations.id"), nullable=False, index=True)
    supplier_name        = Column(String(200))
    supplier_contact     = Column(String(150))
    status               = Column(
        Enum(PurchaseOrderStatus, name="purchase_order_status_enum"),
        default=PurchaseOrderStatus.draft, nullable=False, index=True
    )
    expected_arrival     = Column(DateTime(timezone=True))
    received_at          = Column(DateTime(timezone=True))
    total_cost           = Column(Numeric(10, 2), default=0)   # total cost price
    notes                = Column(Text)
    created_by           = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at           = Column(DateTime(timezone=True), server_default=func.now())
    updated_at           = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    destination_location = relationship("Location", back_populates="purchase_orders")
    creator              = relationship("User",     foreign_keys=[created_by])
    items                = relationship("PurchaseOrderItem", back_populates="purchase_order", cascade="all, delete-orphan")


class PurchaseOrderItem(Base):
    __tablename__ = "purchase_order_items"
    id                = Column(Integer, primary_key=True, index=True)
    purchase_order_id = Column(Integer, ForeignKey("purchase_orders.id"), nullable=False, index=True)
    product_id        = Column(Integer, ForeignKey("products.id"),        nullable=False, index=True)
    quantity_ordered  = Column(Integer, nullable=False, default=1)
    quantity_received = Column(Integer, nullable=False, default=0)  # incremented as stock arrives
    cost_price        = Column(Numeric(10, 2))                       # per unit cost from supplier

    purchase_order = relationship("PurchaseOrder", back_populates="items")
    product        = relationship("Product")
