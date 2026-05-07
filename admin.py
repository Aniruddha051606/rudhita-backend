"""
admin.py  –  Admin / Seller Dashboard  |  Phase 2 Update
==========================================================

Phase 2 new endpoints
---------------------
  POST /admin/orders/{order_id}/fulfill
      Creates a Fulfillment + FulfillmentItems, writes an
      order_shipped InventoryTransaction for each item,
      and marks the order as Shipped.

  POST /admin/orders/bulk-fulfill
      Accepts a list of up to 50 order IDs.
      Returns {"status":"processing"} immediately.
      Hands the actual work to a FastAPI BackgroundTask that
      opens its own DB session (safe for the single-Uvicorn
      Optiplex deployment).

  GET /admin/inventory
      Paginated snapshot of InventoryLevel rows joined with
      product + location names.  Low-stock rows appear first.

All Phase 1 endpoints (dashboard, stats, products, orders CRUD,
waybill, refund, users, audit-log) are preserved unchanged.
"""

import os
import json
import uuid
import logging
from datetime import datetime, timezone
from decimal  import Decimal
from typing   import List, Optional

import razorpay
from fastapi          import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm   import Session, joinedload
from sqlalchemy       import func as sqlfunc

import models
import schemas
from database  import get_db, SessionLocal
from utils     import get_current_user, send_order_confirmation_email
from services.inventory_service import (
    get_primary_location,
    ship_stock,
    get_inventory_snapshot,
    InsufficientCommittedError,
)

logger = logging.getLogger("rudhita")
router = APIRouter(prefix="/admin", tags=["Admin / Seller Dashboard"])


# ── Auth dependency ────────────────────────────────────────────────────────────

def require_admin(current_user: models.User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    return current_user


# ── Audit helper ───────────────────────────────────────────────────────────────

def _audit(
    db:          Session,
    actor:       models.User,
    action:      str,
    target_type: str  = None,
    target_id:   int  = None,
    detail:      dict = None,
):
    try:
        db.add(models.AuditLog(
            actor_id    = actor.id,
            action      = action,
            target_type = target_type,
            target_id   = target_id,
            detail      = json.dumps(detail) if detail else None,
        ))
    except Exception as exc:
        logger.error("Failed to write audit log: %s", exc)


def _get_razorpay() -> razorpay.Client:
    key_id     = os.getenv("RAZORPAY_KEY_ID")
    key_secret = os.getenv("RAZORPAY_KEY_SECRET")
    if not key_id or not key_secret:
        raise HTTPException(status_code=503, detail="Payment gateway not configured.")
    return razorpay.Client(auth=(key_id, key_secret))


# ─────────────────────────────────────────────────────────────────────────────
# ── PHASE 2: FULFILLMENT CORE LOGIC (shared by single + bulk) ────────────────
# ─────────────────────────────────────────────────────────────────────────────

def _fulfill_order_in_session(
    db:            Session,
    order_id:      int,
    location_id:   int,
    carrier:       Optional[str] = None,
    tracking_num:  Optional[str] = None,
    notes:         Optional[str] = None,
    actor_id:      Optional[int] = None,
) -> models.Fulfillment:
    """
    Core fulfillment logic — usable from both the single-order endpoint
    (where the caller manages the session) and the bulk background worker
    (which creates its own session).

    Steps:
      1. Validate order exists and is in a fulfillable state.
      2. Guard against double-fulfillment (idempotency).
      3. Create Fulfillment + FulfillmentItem rows.
      4. Write order_shipped InventoryTransaction for each item
         (legacy_fallback=True handles pre-Phase-1 orders).
      5. Update Order.shipping_status → "Shipped".
      6. Append a TrackingEvent.
      7. Flush (caller commits).

    Raises HTTPException for validation failures.
    Raises InsufficientCommittedError if stock accounting is impossible
    even with the legacy fallback path.
    """
    order = (
        db.query(models.Order)
        .options(joinedload(models.Order.items))
        .filter(models.Order.id == order_id)
        .first()
    )
    if not order:
        raise HTTPException(status_code=404, detail=f"Order #{order_id} not found.")

    # Only fulfil paid orders
    if order.payment_status != "Paid":
        raise HTTPException(
            status_code=400,
            detail=(
                f"Order #{order_id} cannot be fulfilled — "
                f"payment_status='{order.payment_status}' (must be 'Paid')."
            ),
        )

    # Idempotency: don't create a second fulfillment if one already exists
    existing = (
        db.query(models.Fulfillment)
        .filter(
            models.Fulfillment.order_id == order_id,
            models.Fulfillment.status.in_([
                models.FulfillmentStatus.shipped,
                models.FulfillmentStatus.delivered,
                models.FulfillmentStatus.packed,
            ]),
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Order #{order_id} already has an active fulfillment "
                f"(id={existing.id}, status={existing.status.value})."
            ),
        )

    if not order.items:
        raise HTTPException(
            status_code=400,
            detail=f"Order #{order_id} has no items to fulfill.",
        )

    # Create the Fulfillment record
    fulfillment = models.Fulfillment(
        order_id        = order_id,
        location_id     = location_id,
        status          = models.FulfillmentStatus.shipped,
        carrier         = carrier,
        tracking_number = tracking_num,
        notes           = notes,
        shipped_at      = datetime.now(timezone.utc),
    )
    db.add(fulfillment)
    db.flush()  # need fulfillment.id before FulfillmentItems and ledger writes

    # Create FulfillmentItems + write ledger
    for item in order.items:
        db.add(models.FulfillmentItem(
            fulfillment_id = fulfillment.id,
            order_item_id  = item.id,
            quantity       = item.quantity,
        ))

        # Write order_shipped InventoryTransaction
        # legacy_fallback=True: handles orders placed before Phase 1
        ship_stock(
            db,
            product_id      = item.product_id,
            location_id     = location_id,
            quantity        = item.quantity,
            fulfillment_id  = fulfillment.id,
            actor_id        = actor_id,
            legacy_fallback = True,
        )

    # Update order status
    order.shipping_status = "Shipped"
    if tracking_num:
        order.delhivery_waybill = tracking_num

    db.add(models.TrackingEvent(
        order_id    = order_id,
        status      = "Shipped",
        description = (
            f"Order fulfilled and dispatched"
            + (f" via {carrier}" if carrier else "")
            + (f". Tracking: {tracking_num}" if tracking_num else "")
            + "."
        ),
    ))

    logger.info(
        "Order #%s fulfilled  fulfillment_id=%s  carrier=%s  tracking=%s",
        order_id, fulfillment.id, carrier, tracking_num,
    )
    return fulfillment


# ─────────────────────────────────────────────────────────────────────────────
# ── BACKGROUND WORKER for bulk-fulfill ───────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def _bulk_fulfill_worker(
    order_ids:   List[int],
    location_id: int,
    actor_id:    int,
) -> None:
    """
    FastAPI BackgroundTask — opens its own DB session so the
    request session (already closed) is never touched.

    Processes each order independently so a single failure doesn't
    abort the rest. Results are written to the audit log.
    """
    succeeded, failed = [], []

    for oid in order_ids:
        db = SessionLocal()
        try:
            _fulfill_order_in_session(
                db,
                order_id    = oid,
                location_id = location_id,
                actor_id    = actor_id,
            )
            db.commit()
            succeeded.append(oid)
            logger.info("Bulk-fulfill: order #%s succeeded", oid)
        except HTTPException as exc:
            db.rollback()
            failed.append({"order_id": oid, "reason": exc.detail})
            logger.warning("Bulk-fulfill: order #%s SKIPPED — %s", oid, exc.detail)
        except Exception as exc:
            db.rollback()
            failed.append({"order_id": oid, "reason": str(exc)})
            logger.error("Bulk-fulfill: order #%s ERROR — %s", oid, exc)
        finally:
            db.close()

    # Write a single audit record summarising the job
    db = SessionLocal()
    try:
        db.add(models.AuditLog(
            actor_id    = actor_id,
            action      = "bulk_fulfill",
            target_type = "Order",
            target_id   = None,
            detail      = json.dumps({
                "total":     len(order_ids),
                "succeeded": succeeded,
                "failed":    failed,
            }),
        ))
        db.commit()
    except Exception as exc:
        logger.error("Bulk-fulfill: failed to write audit summary: %s", exc)
    finally:
        db.close()

    logger.info(
        "Bulk-fulfill complete: %d succeeded / %d failed",
        len(succeeded), len(failed),
    )


# ─────────────────────────────────────────────────────────────────────────────
# ── 1. Dashboard ──────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/dashboard")
def get_dashboard(
    db: Session = Depends(get_db),
    _:  models.User = Depends(require_admin),
):
    total_orders  = db.query(sqlfunc.count(models.Order.id)).scalar()
    total_revenue = db.query(
        sqlfunc.coalesce(sqlfunc.sum(models.Order.total_amount), 0.0)
    ).filter(models.Order.payment_status == "Paid").scalar()
    total_products = db.query(sqlfunc.count(models.Product.id)).filter(
        models.Product.is_active == True
    ).scalar()
    recent_orders = (
        db.query(models.Order)
        .options(joinedload(models.Order.owner))
        .order_by(models.Order.created_at.desc())
        .limit(10).all()
    )
    return {
        "totalOrders":   total_orders,
        "totalRevenue":  float(total_revenue) if total_revenue else 0.0,
        "totalProducts": total_products,
        "recentOrders": [
            {
                "id":              o.id,
                "customer_name":   o.owner.name  if o.owner else "N/A",
                "total":           float(o.total_amount),
                "shipping_status": o.shipping_status.lower() if o.shipping_status else "pending",
                "payment_status":  o.payment_status,
                "created_at":      o.created_at.isoformat(),
            }
            for o in recent_orders
        ],
    }


# ── 2. Stats ───────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=schemas.DashboardStats)
def get_stats(db: Session = Depends(get_db), _: models.User = Depends(require_admin)):
    return schemas.DashboardStats(
        total_orders       = db.query(sqlfunc.count(models.Order.id)).scalar(),
        pending_orders     = db.query(sqlfunc.count(models.Order.id)).filter(models.Order.shipping_status == "Pending").scalar(),
        shipped_orders     = db.query(sqlfunc.count(models.Order.id)).filter(models.Order.shipping_status == "Shipped").scalar(),
        delivered_orders   = db.query(sqlfunc.count(models.Order.id)).filter(models.Order.shipping_status == "Delivered").scalar(),
        total_revenue      = db.query(sqlfunc.coalesce(sqlfunc.sum(models.Order.total_amount), 0.0)).filter(models.Order.payment_status == "Paid").scalar() or Decimal("0.00"),
        total_products     = db.query(sqlfunc.count(models.Product.id)).filter(models.Product.is_active == True).scalar(),
        low_stock_products = db.query(sqlfunc.count(models.Product.id)).filter(models.Product.stock_quantity < 10, models.Product.is_active == True).scalar(),
        total_users        = db.query(sqlfunc.count(models.User.id)).filter(models.User.is_verified == True).scalar(),
    )


# ── 3. Products ────────────────────────────────────────────────────────────────

@router.get("/products")
def admin_list_products(
    skip:           int  = Query(default=0, ge=0),
    limit:          int  = Query(default=50, ge=1, le=200),
    category:       str  = None,
    low_stock_only: bool = False,
    db: Session = Depends(get_db),
    _:  models.User = Depends(require_admin),
):
    q = db.query(models.Product)
    if category:
        q = q.filter(models.Product.category == category)
    if low_stock_only:
        q = q.filter(models.Product.stock_quantity < 10)
    products = q.order_by(models.Product.created_at.desc()).offset(skip).limit(limit).all()

    def _resp(p):
        pr = schemas.ProductResponse.model_validate(p)
        if p.original_price and p.original_price > p.price:
            pr.discount_percent = int((1 - float(p.price) / float(p.original_price)) * 100)
        return pr

    return {"products": [_resp(p) for p in products]}


@router.post("/products", response_model=schemas.ProductResponse, status_code=201)
def admin_create_product(
    data: schemas.ProductAdminCreate,
    db:   Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    import uuid as _uuid
    sku = data.sku or f"RUD-{_uuid.uuid4().hex[:8].upper()}"
    if db.query(models.Product).filter(models.Product.sku == sku).first():
        sku = f"RUD-{_uuid.uuid4().hex[:8].upper()}"

    product = models.Product(
        sku=sku, name=data.name, description=data.description,
        category=data.category, price=data.price,
        original_price=data.original_price,
        stock_quantity=data.stock_quantity, weight_grams=data.weight_grams,
        image_url=data.image_url,
    )
    db.add(product)
    _audit(db, current_user, "create_product", "Product", None, {"name": data.name, "sku": sku})
    db.commit()
    db.refresh(product)
    pr = schemas.ProductResponse.model_validate(product)
    if product.original_price and product.original_price > product.price:
        pr.discount_percent = int((1 - float(product.price) / float(product.original_price)) * 100)
    return pr


@router.put("/products/{product_id}",   response_model=schemas.ProductResponse)
@router.patch("/products/{product_id}", response_model=schemas.ProductResponse)
def admin_update_product(
    product_id: int,
    update:     schemas.ProductUpdate,
    db:         Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    product = db.query(models.Product).filter(models.Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found.")
    changes = update.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(product, field, value)
    _audit(db, current_user, "update_product", "Product", product_id, changes)
    db.commit()
    pr = schemas.ProductResponse.model_validate(product)
    if product.original_price and product.original_price > product.price:
        pr.discount_percent = int((1 - float(product.price) / float(product.original_price)) * 100)
    return pr


@router.delete("/products/{product_id}")
def admin_delete_product(
    product_id: int,
    db:         Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    product = db.query(models.Product).filter(models.Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found.")
    product.is_active = False
    _audit(db, current_user, "deactivate_product", "Product", product_id, {"name": product.name})
    db.commit()
    return {"status": "success", "message": f"Product '{product.name}' deactivated."}


# ── 4. Orders ──────────────────────────────────────────────────────────────────

@router.get("/orders")
def admin_list_orders(
    skip:            int = Query(default=0, ge=0),
    limit:           int = Query(default=50, ge=1, le=200),
    payment_status:  str = None,
    shipping_status: str = None,
    db: Session = Depends(get_db),
    _:  models.User = Depends(require_admin),
):
    q = (
        db.query(models.Order)
        .options(
            joinedload(models.Order.items).joinedload(models.OrderItem.product),
            joinedload(models.Order.tracking_events),
            joinedload(models.Order.owner),
            joinedload(models.Order.fulfillments),
        )
        .order_by(models.Order.created_at.desc())
    )
    if payment_status:
        q = q.filter(models.Order.payment_status == payment_status)
    if shipping_status:
        q = q.filter(models.Order.shipping_status == shipping_status)
    orders = q.offset(skip).limit(limit).all()

    return {
        "orders": [
            {
                "id":              o.id,
                "customer_name":   o.owner.name  if o.owner else "N/A",
                "customer_email":  o.owner.email if o.owner else None,
                "total":           float(o.total_amount),
                "shipping_status": o.shipping_status,
                "payment_status":  o.payment_status,
                "waybill":         o.delhivery_waybill,
                "razorpay_payment_id": o.razorpay_payment_id,
                "refund_id":       o.razorpay_refund_id,
                "created_at":      o.created_at.isoformat(),
                # Phase 2: show fulfillment summary
                "fulfillment_count": len(o.fulfillments),
                "fulfillment_status": (
                    o.fulfillments[-1].status.value
                    if o.fulfillments else None
                ),
                "item_count": len(o.items),
            }
            for o in orders
        ]
    }


@router.put("/orders/{order_id}")
@router.patch("/orders/{order_id}/status")
def admin_update_order(
    order_id: int,
    update:   schemas.AdminOrderUpdate,
    db:       Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    valid      = {"Pending","Processing","Shipped","Out for Delivery","Delivered","Cancelled","Return Initiated","Returned"}
    normalised = update.status.title()
    if normalised not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid status. Choose: {', '.join(sorted(valid))}")

    order = db.query(models.Order).filter(models.Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")

    prev_status           = order.shipping_status
    order.shipping_status = normalised
    db.add(models.TrackingEvent(order_id=order.id, status=normalised))
    _audit(db, current_user, "update_order_status", "Order", order_id,
           {"from": prev_status, "to": normalised})
    db.commit()
    return {"status": "success", "message": f"Order #{order_id} → '{normalised}'."}


# ── 4a. Waybill ────────────────────────────────────────────────────────────────

@router.patch("/orders/{order_id}/waybill")
def set_waybill(
    order_id: int,
    waybill:  str = Query(min_length=1, max_length=100),
    db:       Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    order = db.query(models.Order).filter(models.Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")

    order.delhivery_waybill = waybill
    order.shipping_status   = "Shipped"
    db.add(models.TrackingEvent(
        order_id    = order.id,
        status      = "Shipped",
        description = f"Dispatched via Delhivery. Waybill: {waybill}",
    ))
    _audit(db, current_user, "set_waybill", "Order", order_id, {"waybill": waybill})
    db.commit()

    try:
        user = db.query(models.User).filter(models.User.id == order.user_id).first()
        if user:
            send_order_confirmation_email(user.email, user.name, order)
    except Exception as exc:
        logger.warning("Could not send shipping notification order #%s: %s", order_id, exc)

    return {"status": "success", "waybill": waybill}


# ── 4b. Refund ─────────────────────────────────────────────────────────────────

@router.post("/orders/{order_id}/refund")
def admin_initiate_refund(
    order_id: int,
    db:       Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    order = db.query(models.Order).filter(models.Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")
    if order.payment_status != "Paid":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot refund order with payment_status='{order.payment_status}'.",
        )
    if order.razorpay_refund_id:
        raise HTTPException(
            status_code=409,
            detail=f"Refund already initiated (refund_id={order.razorpay_refund_id}).",
        )
    if not order.razorpay_payment_id:
        raise HTTPException(status_code=400, detail="No Razorpay payment ID on this order.")

    rz = _get_razorpay()
    try:
        refund = rz.payment.refund(
            order.razorpay_payment_id,
            {
                "amount": int(float(order.total_amount) * 100),
                "notes":  {"reason": "Admin-initiated refund", "order_id": str(order.id)},
            }
        )
    except razorpay.errors.BadRequestError as exc:
        logger.error("Razorpay refund failed order #%s: %s", order_id, exc)
        raise HTTPException(status_code=502, detail=f"Razorpay refund failed: {str(exc)}")

    refund_id                = refund.get("id", "")
    order.razorpay_refund_id = refund_id
    order.payment_status     = "Refunded"
    db.add(models.TrackingEvent(
        order_id    = order.id,
        status      = "Refunded",
        description = (
            f"Full refund of ₹{float(order.total_amount):,.2f} initiated. "
            f"Razorpay Refund ID: {refund_id}."
        ),
    ))
    _audit(db, current_user, "initiate_refund", "Order", order_id, {
        "refund_id":  refund_id,
        "amount":     float(order.total_amount),
        "payment_id": order.razorpay_payment_id,
    })
    db.commit()

    return {
        "status":    "success",
        "refund_id": refund_id,
        "amount":    float(order.total_amount),
        "message":   f"Refund of ₹{float(order.total_amount):,.2f} initiated.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# ── PHASE 2: SINGLE FULFILL ───────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/orders/{order_id}/fulfill", response_model=schemas.FulfillmentResponse)
def admin_fulfill_order(
    order_id:     int,
    payload:      schemas.FulfillOrderRequest,
    db:           Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    """
    Fulfill a single order.

    Creates a Fulfillment record, FulfillmentItem rows, and writes
    order_shipped InventoryTransactions for every OrderItem.

    Idempotent: returns 409 if an active fulfillment already exists.
    Legacy-safe: orders placed before Phase 1 are handled via the
    legacy_fallback path in ship_stock().
    """
    try:
        primary_location = get_primary_location(db)
    except HTTPException:
        raise HTTPException(
            status_code=503,
            detail="Inventory system not ready. No active warehouse found.",
        )

    fulfillment = _fulfill_order_in_session(
        db,
        order_id     = order_id,
        location_id  = primary_location.id,
        carrier      = payload.carrier,
        tracking_num = payload.tracking_number,
        notes        = payload.notes,
        actor_id     = current_user.id,
    )

    _audit(db, current_user, "fulfill_order", "Order", order_id, {
        "fulfillment_id":  fulfillment.id,
        "carrier":         payload.carrier,
        "tracking_number": payload.tracking_number,
    })
    db.commit()

    # Re-fetch with relationships for the response
    db.refresh(fulfillment)
    return schemas.FulfillmentResponse(
        id              = fulfillment.id,
        order_id        = fulfillment.order_id,
        status          = fulfillment.status.value,
        carrier         = fulfillment.carrier,
        tracking_number = fulfillment.tracking_number,
        shipped_at      = fulfillment.shipped_at,
        items=[
            schemas.FulfillmentItemResponse(
                order_item_id = fi.order_item_id,
                quantity      = fi.quantity,
            )
            for fi in fulfillment.items
        ],
    )


# ─────────────────────────────────────────────────────────────────────────────
# ── PHASE 2: BULK FULFILL ─────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/orders/bulk-fulfill", response_model=schemas.BulkFulfillResponse)
def admin_bulk_fulfill(
    payload:          schemas.BulkFulfillRequest,
    background_tasks: BackgroundTasks,
    db:               Session = Depends(get_db),
    current_user:     models.User = Depends(require_admin),
):
    """
    Enqueue fulfillment for up to 50 orders.

    Returns {"status": "processing"} immediately so the admin UI
    doesn't time out on slow hardware.

    The background worker (_bulk_fulfill_worker) opens its own
    SessionLocal per order so each fulfillment is an independent
    transaction — one failure does not abort the rest.

    Progress is visible in:
      • Server logs (INFO level)
      • GET /admin/audit-log (action = 'bulk_fulfill')
    """
    try:
        primary_location = get_primary_location(db)
    except HTTPException:
        raise HTTPException(
            status_code=503,
            detail="Inventory system not ready. No active warehouse found.",
        )

    order_ids = list(dict.fromkeys(payload.order_ids))  # deduplicate, preserve order

    # Log the intention before handing off
    _audit(db, current_user, "bulk_fulfill_enqueued", "Order", None, {
        "count":     len(order_ids),
        "order_ids": order_ids,
    })
    db.commit()

    # Enqueue — returns before the worker starts
    background_tasks.add_task(
        _bulk_fulfill_worker,
        order_ids   = order_ids,
        location_id = primary_location.id,
        actor_id    = current_user.id,
    )

    logger.info(
        "Bulk-fulfill enqueued by admin %s: %d orders",
        current_user.email, len(order_ids),
    )

    return schemas.BulkFulfillResponse(
        status    = "processing",
        message   = (
            f"{len(order_ids)} order(s) queued for fulfillment. "
            "Check the audit log for results."
        ),
        total     = len(order_ids),
        order_ids = order_ids,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ── PHASE 2: INVENTORY DASHBOARD ─────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/inventory")
def admin_list_inventory(
    skip:  int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db:    Session = Depends(get_db),
    _:     models.User = Depends(require_admin),
):
    """
    Paginated inventory snapshot.
    Rows are ordered by available ASC so low-stock items appear first.
    """
    rows = get_inventory_snapshot(db, skip=skip, limit=limit)
    return {"inventory": rows, "count": len(rows)}


# ── 5. Users ───────────────────────────────────────────────────────────────────

@router.get("/users")
def admin_list_users(
    skip:  int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    db:    Session = Depends(get_db),
    _:     models.User = Depends(require_admin),
):
    users = db.query(models.User).order_by(models.User.created_at.desc()).offset(skip).limit(limit).all()
    return {
        "users": [
            {
                "id":          u.id,
                "name":        u.name,
                "email":       u.email,
                "phone":       u.phone,
                "is_verified": u.is_verified,
                "is_admin":    u.is_admin,
                "created_at":  u.created_at.isoformat() if u.created_at else None,
            }
            for u in users
        ]
    }


@router.post("/users/{user_id}/admin")
@router.patch("/users/{user_id}/make-admin")
def make_admin(
    user_id: int,
    db:      Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot modify your own admin status.")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.is_admin = True
    _audit(db, current_user, "grant_admin", "User", user_id, {"target_email": user.email})
    db.commit()
    logger.warning("Admin granted to user %s (%s) by %s", user.id, user.email, current_user.email)
    return {"status": "success", "message": f"{user.name} is now an admin."}


# ── 6. Low-stock alerts ────────────────────────────────────────────────────────

@router.get("/alerts/low-stock", response_model=List[schemas.ProductStockAlert])
def low_stock_alerts(
    threshold: int = Query(default=10, ge=1, le=100),
    db:        Session = Depends(get_db),
    _:         models.User = Depends(require_admin),
):
    return (
        db.query(models.Product)
        .filter(models.Product.stock_quantity <= threshold, models.Product.is_active == True)
        .order_by(models.Product.stock_quantity.asc())
        .all()
    )


# ── 7. Audit log ───────────────────────────────────────────────────────────────

@router.get("/audit-log")
def get_audit_log(
    skip:  int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    db:    Session = Depends(get_db),
    _:     models.User = Depends(require_admin),
):
    logs = (
        db.query(models.AuditLog)
        .order_by(models.AuditLog.created_at.desc())
        .offset(skip).limit(limit).all()
    )
    return {
        "logs": [
            {
                "id":          l.id,
                "actor_id":    l.actor_id,
                "action":      l.action,
                "target_type": l.target_type,
                "target_id":   l.target_id,
                "detail":      l.detail,
                "created_at":  l.created_at.isoformat(),
            }
            for l in logs
        ]
    }
