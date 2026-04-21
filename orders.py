"""
orders.py  —  Order Routes (PATCHED)

Changes from audit:
  1. create_order_from_frontend(): SELECT FOR UPDATE on product rows — prevents overselling
  2. confirm_payment():            Razorpay HMAC-SHA256 signature verification — REQUIRED
  3. confirm_payment():            Idempotency guard — cannot overwrite a "Paid" order
  4. list_my_orders():             Single subquery for item counts — fixes N+1
  5. _clear_cart():               Opens its own DB session — fixes stale-session crash
"""

import os
import hmac
import hashlib
import logging
import razorpay

from fastapi          import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy       import select, func as sqlfunc
from sqlalchemy.orm   import Session, joinedload
from typing           import List

import models
import schemas
from database  import get_db, SessionLocal
from utils     import get_current_user

logger = logging.getLogger("rudhita")
router = APIRouter(prefix="/orders", tags=["Orders"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_razorpay() -> razorpay.Client:
    key_id     = os.getenv("RAZORPAY_KEY_ID")
    key_secret = os.getenv("RAZORPAY_KEY_SECRET")
    if not key_id or not key_secret:
        raise HTTPException(status_code=503, detail="Payment gateway not configured.")
    return razorpay.Client(auth=(key_id, key_secret))


def _format_address(addr: schemas.CheckoutAddress) -> str:
    return f"{addr.name}, {addr.phone}, {addr.street}, {addr.city}, {addr.state} - {addr.pincode}"


# FIX: background task creates its own session — the request session is closed by now
def _clear_cart(user_id: int) -> None:
    db = SessionLocal()
    try:
        cart = db.query(models.Cart).filter(models.Cart.user_id == user_id).first()
        if cart:
            db.query(models.CartItem).filter(models.CartItem.cart_id == cart.id).delete()
            db.commit()
    except Exception as exc:
        logger.error("Failed to clear cart for user %s: %s", user_id, exc)
        db.rollback()
    finally:
        db.close()


# ── 1. Create order ───────────────────────────────────────────────────────────

@router.post("/", response_model=dict, status_code=201)
def create_order_from_frontend(
    order_data:       schemas.FrontendOrderCreate,
    background_tasks: BackgroundTasks,
    db:               Session = Depends(get_db),
    current_user:     models.User = Depends(get_current_user),
):
    """
    Reads cart, creates a Razorpay order, and persists everything atomically.

    FIX: Uses SELECT FOR UPDATE on each product row so two simultaneous checkouts
         for the last item in stock cannot both succeed.
    """
    cart = (
        db.query(models.Cart)
        .options(joinedload(models.Cart.items))
        .filter(models.Cart.user_id == current_user.id)
        .first()
    )
    if not cart or not cart.items:
        raise HTTPException(status_code=400, detail="Your cart is empty.")

    total       = 0
    order_items = []

    for cart_item in cart.items:
        # FIX: lock the product row for this transaction — prevents race conditions
        product = db.execute(
            select(models.Product)
            .where(models.Product.id == cart_item.product_id)
            .with_for_update()                         # <-- row-level lock
        ).scalar_one_or_none()

        if not product or not product.is_active:
            raise HTTPException(
                status_code=400,
                detail=f"Product id={cart_item.product_id} is no longer available."
            )
        if product.stock_quantity < cart_item.quantity:
            raise HTTPException(
                status_code=400,
                detail=f"Only {product.stock_quantity} unit(s) of '{product.name}' left in stock."
            )

        total += float(product.price) * cart_item.quantity
        order_items.append((product, cart_item.quantity))

    shipping_address = _format_address(order_data.address)

    rz       = _get_razorpay()
    rz_order = rz.order.create({
        "amount":   int(round(total * 100)),   # paise, no float drift
        "currency": "INR",
        "receipt":  f"rudhita_user_{current_user.id}",
    })

    new_order = models.Order(
        user_id            = current_user.id,
        total_amount       = round(total, 2),
        shipping_address   = shipping_address,
        razorpay_order_id  = rz_order["id"],
        payment_status     = "Pending",
        shipping_status    = "Pending",
    )
    db.add(new_order)
    db.flush()  # get new_order.id before creating items

    for product, qty in order_items:
        db.add(models.OrderItem(
            order_id          = new_order.id,
            product_id        = product.id,
            quantity          = qty,
            price_at_purchase = product.price,
        ))
        product.stock_quantity -= qty   # safe: row is locked

    db.add(models.TrackingEvent(
        order_id    = new_order.id,
        status      = "Order Placed",
        description = "Your order has been received and is being processed.",
    ))
    db.commit()  # lock released here; all stock decrements are now visible atomically

    # FIX: pass user_id not db — background task opens its own session
    background_tasks.add_task(_clear_cart, current_user.id)

    logger.info("Order #%s created for user %s, Razorpay=%s", new_order.id, current_user.id, rz_order["id"])

    return {
        "order_id":         new_order.id,
        "razorpay_order_id": rz_order["id"],
        "amount":           round(total, 2),
        "currency":         "INR",
        "key_id":           os.getenv("RAZORPAY_KEY_ID"),
    }


# ── 2. Legacy checkout route (kept for compatibility) ─────────────────────────

@router.post("/checkout", response_model=dict, status_code=201)
def checkout(
    order_data:       schemas.OrderCreate,
    background_tasks: BackgroundTasks,
    db:               Session = Depends(get_db),
    current_user:     models.User = Depends(get_current_user),
):
    """Legacy route — same race-condition fixes applied."""
    cart = (
        db.query(models.Cart)
        .options(joinedload(models.Cart.items))
        .filter(models.Cart.user_id == current_user.id)
        .first()
    )
    if not cart or not cart.items:
        raise HTTPException(status_code=400, detail="Your cart is empty.")

    total       = 0
    order_items = []

    for cart_item in cart.items:
        product = db.execute(
            select(models.Product)
            .where(models.Product.id == cart_item.product_id)
            .with_for_update()
        ).scalar_one_or_none()

        if not product or not product.is_active:
            raise HTTPException(status_code=400, detail=f"Product unavailable.")
        if product.stock_quantity < cart_item.quantity:
            raise HTTPException(status_code=400, detail=f"Insufficient stock for '{product.name}'.")

        total += float(product.price) * cart_item.quantity
        order_items.append((product, cart_item.quantity))

    rz       = _get_razorpay()
    rz_order = rz.order.create({"amount": int(round(total * 100)), "currency": "INR"})

    new_order = models.Order(
        user_id           = current_user.id,
        total_amount      = round(total, 2),
        shipping_address  = order_data.shipping_address,
        razorpay_order_id = rz_order["id"],
        payment_status    = "Pending",
        shipping_status   = "Pending",
    )
    db.add(new_order)
    db.flush()

    for product, qty in order_items:
        db.add(models.OrderItem(
            order_id=new_order.id, product_id=product.id,
            quantity=qty, price_at_purchase=product.price,
        ))
        product.stock_quantity -= qty

    db.add(models.TrackingEvent(
        order_id=new_order.id, status="Order Placed",
        description="Your order has been received.",
    ))
    db.commit()
    background_tasks.add_task(_clear_cart, current_user.id)

    return {
        "order_id": new_order.id,
        "razorpay_order_id": rz_order["id"],
        "amount": round(total, 2),
        "currency": "INR",
        "key_id": os.getenv("RAZORPAY_KEY_ID"),
    }


# ── 3. Confirm payment ────────────────────────────────────────────────────────

@router.post("/{order_id}/confirm-payment")
def confirm_payment(
    order_id: int,
    payload:  schemas.PaymentConfirm,      # FIX: new schema — requires all 3 Razorpay fields
    db:       Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    FIX 1: Verifies the Razorpay HMAC-SHA256 signature before marking as Paid.
            Without this any user can send fake payment data and get goods for free.
    FIX 2: Idempotency guard — a Paid order cannot be downgraded.
    """
    order = db.query(models.Order).filter(
        models.Order.id      == order_id,
        models.Order.user_id == current_user.id,
    ).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")

    # Verify the order belongs to the Razorpay order we created
    if order.razorpay_order_id != payload.razorpay_order_id:
        raise HTTPException(status_code=400, detail="Razorpay order ID mismatch.")

    # FIX: Idempotency — never overwrite a completed payment
    if order.payment_status == "Paid":
        return {"status": "success", "message": "Order is already marked as paid."}

    # FIX: Cryptographic signature verification
    key_secret = os.getenv("RAZORPAY_KEY_SECRET", "").encode()
    body       = f"{payload.razorpay_order_id}|{payload.razorpay_payment_id}".encode()
    expected   = hmac.new(key_secret, body, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, payload.razorpay_signature):
        logger.warning(
            "Payment signature mismatch for order #%s, user #%s",
            order_id, current_user.id
        )
        raise HTTPException(status_code=400, detail="Payment verification failed. Signature mismatch.")

    order.payment_status      = "Paid"
    order.razorpay_payment_id = payload.razorpay_payment_id
    order.shipping_status     = "Processing"
    db.add(models.TrackingEvent(
        order_id    = order.id,
        status      = "Payment Confirmed",
        description = "Payment received and verified. Order is being prepared.",
    ))
    db.commit()

    logger.info("Payment confirmed for order #%s (payment=%s)", order_id, payload.razorpay_payment_id)
    return {"status": "success", "message": f"Order #{order_id} payment confirmed."}


# ── 4. List my orders ─────────────────────────────────────────────────────────

@router.get("/", response_model=schemas.OrderListResponse)
def list_my_orders(
    skip:  int = 0,
    limit: int = 20,
    db:    Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    FIX: Replaces the N+1 loop (one COUNT query per order) with a single
         GROUP BY subquery — all item counts fetched in one DB round-trip.
    """
    # Subquery: item_count per order
    item_count_sq = (
        db.query(
            models.OrderItem.order_id,
            sqlfunc.count(models.OrderItem.id).label("item_count"),
        )
        .group_by(models.OrderItem.order_id)
        .subquery()
    )

    rows = (
        db.query(models.Order, item_count_sq.c.item_count)
        .outerjoin(item_count_sq, models.Order.id == item_count_sq.c.order_id)
        .filter(models.Order.user_id == current_user.id)
        .order_by(models.Order.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    result = [
        schemas.OrderSummaryResponse(
            id              = o.id,
            total_amount    = o.total_amount,
            payment_status  = o.payment_status,
            shipping_status = o.shipping_status,
            item_count      = count or 0,
            created_at      = o.created_at,
        )
        for o, count in rows
    ]
    return schemas.OrderListResponse(orders=result)


# ── 5. Order detail ───────────────────────────────────────────────────────────

@router.get("/{order_id}", response_model=schemas.OrderResponse)
def get_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    order = (
        db.query(models.Order)
        .options(
            joinedload(models.Order.items).joinedload(models.OrderItem.product),
            joinedload(models.Order.tracking_events),
        )
        .filter(models.Order.id == order_id, models.Order.user_id == current_user.id)
        .first()
    )
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")
    return order


# ── 6. Track order ────────────────────────────────────────────────────────────

@router.get("/{order_id}/track", response_model=schemas.TrackingResponse)
def track_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    order = db.query(models.Order).filter(
        models.Order.id == order_id, models.Order.user_id == current_user.id
    ).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")

    events = (
        db.query(models.TrackingEvent)
        .filter(models.TrackingEvent.order_id == order_id)
        .order_by(models.TrackingEvent.created_at.asc())
        .all()
    )
    return schemas.TrackingResponse(
        order_id        = order.id,
        shipping_status = order.shipping_status,
        waybill         = order.delhivery_waybill,
        events          = events,
    )


# ── 7. Cancel order ───────────────────────────────────────────────────────────

@router.post("/{order_id}/cancel")
def cancel_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    order = db.query(models.Order).filter(
        models.Order.id == order_id, models.Order.user_id == current_user.id
    ).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")
    if order.shipping_status not in ("Pending", "Processing"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel an order that is '{order.shipping_status}'."
        )

    order.shipping_status = "Cancelled"
    order.payment_status  = "Refund Initiated" if order.payment_status == "Paid" else "Cancelled"

    # Restore stock for each item (lock rows to be safe)
    for item in order.items:
        product = db.execute(
            select(models.Product)
            .where(models.Product.id == item.product_id)
            .with_for_update()
        ).scalar_one_or_none()
        if product:
            product.stock_quantity += item.quantity

    db.add(models.TrackingEvent(
        order_id    = order.id,
        status      = "Cancelled",
        description = "Order cancelled by customer.",
    ))
    db.commit()
    return {"status": "success", "message": "Order cancelled and stock restored."}
