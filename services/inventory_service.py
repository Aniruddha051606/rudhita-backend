"""
services/inventory_service.py  –  Rudhita OMS  |  Phase 2
===========================================================
The single source of truth for ALL inventory mutations.

RULE: Nothing outside this module may directly write to
      InventoryLevel or InventoryTransaction.
      Routes call the public functions here; this module
      guarantees atomicity, row-locking, and audit-trail
      consistency.

Public API
----------
  get_primary_location(db)
      Returns the primary warehouse Location (code WH-MAIN-01).

  ensure_inventory_level(db, product_id, location_id, *, locked)
      Upserts the InventoryLevel cache row. Bootstraps from
      product.stock_quantity for products that pre-date Phase 1.

  commit_stock(db, *, product_id, location_id, quantity, order_id, actor_id)
      Checkout path  → available - qty,  committed + qty.
      Locks the InventoryLevel row with SELECT FOR UPDATE.
      Raises InsufficientStockError if available < quantity.

  ship_stock(db, *, product_id, location_id, quantity, fulfillment_id, actor_id)
      Fulfillment path → committed - qty.
      Raises InsufficientCommittedError if committed < quantity.

  release_committed_stock(db, *, product_id, location_id, quantity, order_id, actor_id)
      Cancellation path → committed - qty, available + qty.
      Gracefully handles legacy orders (placed before Phase 1)
      that never had committed stock.

DOUBLE-ENTRY GUARANTEE
  Every stock movement writes TWO ledger rows:
    debit  row  (quantity_delta < 0 on source bucket)
    credit row  (quantity_delta > 0 on destination bucket)
  The exception is order_shipped: only one row is written
  because committed stock simply "leaves" the system.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy import func as sqlfunc, select
from sqlalchemy.orm import Session

import models

logger = logging.getLogger("rudhita.inventory")


# ─────────────────────────────────────────────────────────────────────────────
# CUSTOM EXCEPTIONS
# ─────────────────────────────────────────────────────────────────────────────

class InsufficientStockError(Exception):
    """Raised when available stock < requested quantity."""
    def __init__(self, product_name: str, available: int, requested: int):
        self.product_name = product_name
        self.available    = available
        self.requested    = requested
        super().__init__(
            f"Insufficient available stock for '{product_name}': "
            f"need {requested}, have {available}."
        )


class InsufficientCommittedError(Exception):
    """Raised when committed stock < quantity to be shipped."""
    def __init__(self, product_name: str, committed: int, requested: int):
        self.product_name = product_name
        self.committed    = committed
        self.requested    = requested
        super().__init__(
            f"Committed stock too low for '{product_name}': "
            f"need {requested}, committed {committed}."
        )


# ─────────────────────────────────────────────────────────────────────────────
# PRIMARY LOCATION RESOLUTION
# ─────────────────────────────────────────────────────────────────────────────

def get_primary_location(db: Session) -> models.Location:
    """
    Returns the primary warehouse Location seeded by migration_phase1.sql
    (code = 'WH-MAIN-01').  Falls back to any active warehouse.

    Not cached at module-level so server restarts and location deactivations
    are always reflected without needing a restart.
    """
    loc = (
        db.query(models.Location)
        .filter(
            models.Location.code      == "WH-MAIN-01",
            models.Location.is_active == True,
        )
        .first()
    )

    if loc is None:
        # Fallback: first active warehouse by PK
        loc = (
            db.query(models.Location)
            .filter(models.Location.is_active == True)
            .order_by(models.Location.id.asc())
            .first()
        )

    if loc is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "No active warehouse location found. "
                "Run migration_phase1.sql to seed the primary location."
            ),
        )

    return loc


# ─────────────────────────────────────────────────────────────────────────────
# INVENTORY LEVEL BOOTSTRAP
# ─────────────────────────────────────────────────────────────────────────────

def ensure_inventory_level(
    db:          Session,
    product_id:  int,
    location_id: int,
    *,
    locked: bool = False,
) -> models.InventoryLevel:
    """
    Returns the InventoryLevel row for (product_id, location_id).
    Creates the row if it doesn't exist, bootstrapping the available
    bucket from Product.stock_quantity (for pre-Phase-1 products).

    Pass locked=True to issue a SELECT ... FOR UPDATE on the row
    — required any time you intend to mutate it in the same transaction.
    """
    stmt = (
        select(models.InventoryLevel)
        .where(
            models.InventoryLevel.product_id  == product_id,
            models.InventoryLevel.location_id == location_id,
        )
    )
    if locked:
        stmt = stmt.with_for_update()

    level = db.execute(stmt).scalar_one_or_none()

    if level is None:
        # Bootstrap available from legacy stock_quantity cache
        product   = db.get(models.Product, product_id)
        seed_qty  = int(product.stock_quantity or 0) if product else 0

        level = models.InventoryLevel(
            product_id  = product_id,
            location_id = location_id,
            available   = seed_qty,
            committed   = 0,
            unavailable = 0,
        )
        db.add(level)
        db.flush()  # assign PK before any FK referencing it

        logger.info(
            "Bootstrapped InventoryLevel product_id=%s location_id=%s available=%s",
            product_id, location_id, seed_qty,
        )

        # If we bootstrapped, re-fetch with lock so the caller has a live row
        if locked:
            stmt  = (
                select(models.InventoryLevel)
                .where(models.InventoryLevel.id == level.id)
                .with_for_update()
            )
            level = db.execute(stmt).scalar_one()

    return level


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _write_txn(
    db:               Session,
    *,
    product_id:       int,
    location_id:      int,
    transaction_type: models.InventoryTransactionType,
    bucket:           models.InventoryBucket,
    quantity_delta:   int,
    reference_type:   Optional[str] = None,
    reference_id:     Optional[int] = None,
    notes:            Optional[str] = None,
    created_by:       Optional[int] = None,
) -> models.InventoryTransaction:
    """Appends one immutable ledger row.  Does NOT touch InventoryLevel."""
    txn = models.InventoryTransaction(
        product_id       = product_id,
        location_id      = location_id,
        transaction_type = transaction_type,
        bucket           = bucket,
        quantity_delta   = quantity_delta,
        reference_type   = reference_type,
        reference_id     = reference_id,
        notes            = notes,
        created_by       = created_by,
    )
    db.add(txn)
    return txn


def _refresh_product_cache(db: Session, product_id: int) -> None:
    """
    Recalculates Product.stock_quantity as the SUM of all
    InventoryLevel.available rows for this product.

    Keeps the legacy cache correct for old admin routes that
    read Product.stock_quantity directly.
    """
    total = (
        db.query(
            sqlfunc.coalesce(sqlfunc.sum(models.InventoryLevel.available), 0)
        )
        .filter(models.InventoryLevel.product_id == product_id)
        .scalar()
    ) or 0

    product = db.get(models.Product, product_id)
    if product:
        product.stock_quantity = int(total)


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC SERVICE FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def commit_stock(
    db:          Session,
    *,
    product_id:  int,
    location_id: int,
    quantity:    int,
    order_id:    int,
    actor_id:    Optional[int] = None,
) -> None:
    """
    CHECKOUT path — moves `quantity` from available → committed.

    Acquires a row-level lock on InventoryLevel before reading
    available so that two simultaneous checkouts for the last unit
    cannot both pass the stock check.

    Raises InsufficientStockError if available < quantity.
    """
    if quantity <= 0:
        return

    level = ensure_inventory_level(db, product_id, location_id, locked=True)

    if level.available < quantity:
        product = db.get(models.Product, product_id)
        raise InsufficientStockError(
            product_name = getattr(product, "name", f"product #{product_id}"),
            available    = level.available,
            requested    = quantity,
        )

    # ── Mutate cached buckets ─────────────────────────────────────────────
    level.available -= quantity
    level.committed += quantity

    # ── Write double-entry ledger rows ────────────────────────────────────
    note = f"Committed at checkout for order #{order_id}"

    _write_txn(
        db,
        product_id       = product_id,
        location_id      = location_id,
        transaction_type = models.InventoryTransactionType.order_committed,
        bucket           = models.InventoryBucket.available,
        quantity_delta   = -quantity,
        reference_type   = "order",
        reference_id     = order_id,
        notes            = note,
        created_by       = actor_id,
    )
    _write_txn(
        db,
        product_id       = product_id,
        location_id      = location_id,
        transaction_type = models.InventoryTransactionType.order_committed,
        bucket           = models.InventoryBucket.committed,
        quantity_delta   = +quantity,
        reference_type   = "order",
        reference_id     = order_id,
        notes            = note,
        created_by       = actor_id,
    )

    logger.debug(
        "commit_stock  product=%s  order=%s  qty=%s  → avail=%s  committed=%s",
        product_id, order_id, quantity, level.available, level.committed,
    )


def ship_stock(
    db:             Session,
    *,
    product_id:     int,
    location_id:    int,
    quantity:       int,
    fulfillment_id: int,
    actor_id:       Optional[int] = None,
    legacy_fallback: bool = False,
) -> None:
    """
    FULFILLMENT path — removes `quantity` from the committed bucket.
    The stock has physically left the warehouse.

    legacy_fallback=True:
      For orders placed before Phase 1 that have committed=0,
      falls back to deducting from available directly.
      The admin endpoint passes this when fulfilling legacy orders.

    Raises InsufficientCommittedError if committed < quantity
    AND legacy_fallback is False.
    """
    if quantity <= 0:
        return

    level = ensure_inventory_level(db, product_id, location_id, locked=True)

    if level.committed < quantity:
        if legacy_fallback and level.available >= quantity:
            # Legacy order: deduct from available directly
            logger.warning(
                "ship_stock LEGACY FALLBACK: product=%s fulfillment=%s "
                "committed=%s < qty=%s — deducting from available",
                product_id, fulfillment_id, level.committed, quantity,
            )
            level.available -= quantity
            _write_txn(
                db,
                product_id       = product_id,
                location_id      = location_id,
                transaction_type = models.InventoryTransactionType.order_shipped,
                bucket           = models.InventoryBucket.available,
                quantity_delta   = -quantity,
                reference_type   = "fulfillment",
                reference_id     = fulfillment_id,
                notes            = (
                    f"Legacy fulfillment #{fulfillment_id} — "
                    "no committed stock (pre-Phase-1 order)"
                ),
                created_by       = actor_id,
            )
        else:
            product = db.get(models.Product, product_id)
            raise InsufficientCommittedError(
                product_name = getattr(product, "name", f"product #{product_id}"),
                committed    = level.committed,
                requested    = quantity,
            )
    else:
        level.committed -= quantity
        _write_txn(
            db,
            product_id       = product_id,
            location_id      = location_id,
            transaction_type = models.InventoryTransactionType.order_shipped,
            bucket           = models.InventoryBucket.committed,
            quantity_delta   = -quantity,
            reference_type   = "fulfillment",
            reference_id     = fulfillment_id,
            notes            = f"Stock shipped via fulfillment #{fulfillment_id}",
            created_by       = actor_id,
        )

    # Keep legacy cache in sync
    _refresh_product_cache(db, product_id)

    logger.debug(
        "ship_stock  product=%s  fulfillment=%s  qty=%s  → committed=%s",
        product_id, fulfillment_id, quantity, level.committed,
    )


def release_committed_stock(
    db:          Session,
    *,
    product_id:  int,
    location_id: int,
    quantity:    int,
    order_id:    int,
    actor_id:    Optional[int] = None,
) -> None:
    """
    CANCELLATION path — moves stock back from committed → available.

    Handles legacy orders (committed = 0) by restoring directly to
    available so cancelling a pre-Phase-1 order never fails.
    """
    if quantity <= 0:
        return

    level      = ensure_inventory_level(db, product_id, location_id, locked=True)
    to_release = min(quantity, level.committed)
    note       = f"Stock released on cancellation of order #{order_id}"

    if to_release > 0:
        level.committed -= to_release
        level.available += to_release

        _write_txn(
            db,
            product_id       = product_id,
            location_id      = location_id,
            transaction_type = models.InventoryTransactionType.order_committed,
            bucket           = models.InventoryBucket.committed,
            quantity_delta   = -to_release,
            reference_type   = "order",
            reference_id     = order_id,
            notes            = note,
            created_by       = actor_id,
        )
        _write_txn(
            db,
            product_id       = product_id,
            location_id      = location_id,
            transaction_type = models.InventoryTransactionType.order_committed,
            bucket           = models.InventoryBucket.available,
            quantity_delta   = +to_release,
            reference_type   = "order",
            reference_id     = order_id,
            notes            = note,
            created_by       = actor_id,
        )
    else:
        # Legacy order: nothing was committed, just restore to available
        remaining = quantity   # full qty back to available
        level.available += remaining
        _write_txn(
            db,
            product_id       = product_id,
            location_id      = location_id,
            transaction_type = models.InventoryTransactionType.manual_adjustment_in,
            bucket           = models.InventoryBucket.available,
            quantity_delta   = +remaining,
            reference_type   = "order",
            reference_id     = order_id,
            notes            = f"Legacy stock restore on cancellation of order #{order_id}",
            created_by       = actor_id,
        )

    _refresh_product_cache(db, product_id)

    logger.debug(
        "release_committed_stock  product=%s  order=%s  released=%s  "
        "→ avail=%s  committed=%s",
        product_id, order_id, to_release, level.available, level.committed,
    )


def get_inventory_snapshot(
    db:   Session,
    skip: int = 0,
    limit: int = 100,
) -> list[dict]:
    """
    Returns a flat list of inventory levels joined with product and location
    names for the admin inventory dashboard.  O(1) per row — no lazy loading.
    """
    rows = (
        db.query(
            models.InventoryLevel,
            models.Product.name.label("product_name"),
            models.Product.sku.label("sku"),
            models.Location.name.label("location_name"),
        )
        .join(models.Product,  models.InventoryLevel.product_id  == models.Product.id)
        .join(models.Location, models.InventoryLevel.location_id == models.Location.id)
        .filter(models.Product.is_active == True)
        .order_by(models.InventoryLevel.available.asc())   # low-stock first
        .offset(skip)
        .limit(limit)
        .all()
    )

    return [
        {
            "product_id":    level.product_id,
            "product_name":  product_name,
            "sku":           sku,
            "location_id":   level.location_id,
            "location_name": location_name,
            "available":     level.available,
            "committed":     level.committed,
            "unavailable":   level.unavailable,
            "total_on_hand": level.available + level.committed + level.unavailable,
        }
        for level, product_name, sku, location_name in rows
    ]
