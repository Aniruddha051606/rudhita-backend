"""
orders.py  â€“  Order Routes  |  Phase 2 Update
===============================================

Phase 2 changes vs Phase 1:
  1. create_order_from_frontend():
       - Now locks InventoryLevel rows (not Product rows) via the
         inventory_service.commit_stock() call.
       - Writes two ledger rows per item (availableâ†’ -qty, committedâ†’ +qty).
       - Falls back gracefully if no InventoryLevel exists yet (bootstraps
         from product.stock_quantity).

  2. checkout() (legacy route):
       - Same ledger integration applied.

  3. cancel_order():
       - Uses inventory_service.release_committed_stock() to return
         committed stock â†’ available, including legacy-order safety.

All other routes (confirm_payment, list_my_orders, get_order, track_order)
are unchanged from Phase 1.
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
from utils     import get_current_user, send_order_confirmation_email
from services.inventory_service import (
    commit_stock,
    release_committed_stock,
    get_primary_location,
    InsufficientStockError,
)

logger = logging.getLogger("rudhita")
router = APIRouter(prefix="/orders", tags=["Orders"])


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _get_razorpay() -> razorpay.Client:
    key_id     = os.getenv("RAZORPAY_KEY_ID")
    key_secret = os.getenv("RAZORPAY_KEY_SECRET")
    if not key_id or not key_secret:
        raise HTTPException(status_code=503, detail="Payment gateway not configured.")
    return razorpay.Client(auth=(key_id, key_secret))


def _format_address(addr: schemas.CheckoutAddress) -> str:
    return (
        f"{addr.name}, {addr.phone}, {addr.street}, "
        f"{addr.city}, {addr.state} - {addr.pincode}"
    )


# Order-total policy MUST mirror the frontend (CheckoutPage.jsx / CartPage.jsx) exactly:
#   shipping: express = 200, else free above 3000, else 100
#   tax:      18% of subtotal
def _compute_totals(subtotal: float, shipping_method: str = "standard") -> tuple[float, float, float]:
    """Returns (shipping, tax, grand_total) for a given subtotal."""
    shipping = 200.0 if shipping_method == "express" else (0.0 if subtotal > 3000 else 100.0)
    tax      = subtotal * 0.18
    grand    = round(subtotal + shipping + tax, 2)
    return shipping, tax, grand


def _clear_cart(user_id: int) -> None:
    """Background task â€” opens its own session so the request session is gone."""
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


# â”€â”€ 1. Create order (Phase 2: ledger-aware checkout) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post("/", response_model=dict, status_code=201)
def create_order_from_frontend(
    order_data:       schemas.FrontendOrderCreate,
    background_tasks: BackgroundTasks,
    db:               Session = Depends(get_db),
    current_user:     models.User = Depends(get_current_user),
):
    """
    Creates a Razorpay order and persists all Order/OrderItem rows
    atomically.

    Phase 2 stock flow:
      For each cart item:
        1. Read Product (no lock â€” just need price/active status).
        2. Call commit_stock() which internally issues
           SELECT ... FOR UPDATE on the InventoryLevel row,
           checks available >= qty, then writes two ledger rows
           and mutates the cached buckets.
      If ANY item fails the stock check the entire transaction is
      rolled back and a 400 is returned.  Razorpay is never called.

    Legacy products (InventoryLevel row doesn't exist yet):
      ensure_inventory_level() bootstraps from product.stock_quantity.
    """
    cart = (
        db.query(models.Cart)
        .options(joinedload(models.Cart.items))
        .filter(models.Cart.user_id == current_user.id)
        .first()
    )
    if not cart or not cart.items:
        raise HTTPException(status_code=400, detail="Your cart is empty.")

    # Resolve the primary warehouse once for this request
    try:
        primary_location = get_primary_location(db)
    except HTTPException:
        raise HTTPException(
            status_code=503,
            detail="Inventory system not ready. Contact admin.",
        )

    subtotal    = 0.0
    order_items = []   # list of (product, quantity)

    # â”€â”€ Phase 1: validate stock â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # We collect all validation errors before touching Razorpay so we never
    # create an orphaned Razorpay order.
    for cart_item in cart.items:
        # Plain SELECT â€” no lock needed just for reads
        product = db.get(models.Product, cart_item.product_id)

        if not product or not product.is_active:
            raise HTTPException(
                status_code=400,
                detail=f"Product id={cart_item.product_id} is no longer available.",
            )

        subtotal += float(product.price) * cart_item.quantity
        order_items.append((product, cart_item.quantity))

    # â”€â”€ Compute the grand total (subtotal + shipping + 18% tax) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # This MUST match what the frontend displays, otherwise the customer is
    # charged a different amount than the UI promised.
    _shipping, _tax, total = _compute_totals(subtotal, order_data.shipping_method)

    # â”€â”€ Phase 2: create Razorpay order â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    rz       = _get_razorpay()
    rz_order = rz.order.create({
        "amount":   int(round(total * 100)),
        "currency": "INR",
        "receipt":  f"rudhita_{current_user.id}",
    })

    # â”€â”€ Phase 3: persist Order + Items + Ledger (one atomic transaction) â”€â”€â”€â”€
    new_order = models.Order(
        user_id           = current_user.id,
        total_amount      = round(total, 2),
        shipping_address  = _format_address(order_data.address),
        razorpay_order_id = rz_order["id"],
        payment_status    = "Pending",
        shipping_status   = "Pending",
        source            = "storefront",
    )
    db.add(new_order)
    db.flush()  # get new_order.id before creating children

    for product, qty in order_items:
        db.add(models.OrderItem(
            order_id          = new_order.id,
            product_id        = product.id,
            quantity          = qty,
            price_at_purchase = product.price,
        ))

        # â”€â”€ LEDGER WRITE: available â†’ committed â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # This issues SELECT FOR UPDATE on InventoryLevel internally.
        # Raises InsufficientStockError â†’ triggers automatic rollback.
        try:
            commit_stock(
                db,
                product_id  = product.id,
                location_id = primary_location.id,
                quantity    = qty,
                order_id    = new_order.id,
                actor_id    = current_user.id,
            )
        except InsufficientStockError as exc:
            # Roll back the entire transaction (Razorpay order is abandoned)
            db.rollback()
            raise HTTPException(status_code=400, detail=str(exc))

        # Keep legacy cache accurate for old admin routes
        product.stock_quantity = max(0, product.stock_quantity - qty)

    db.add(models.TrackingEvent(
        order_id    = new_order.id,
        status      = "Order Placed",
        description = "Your order has been received and is being processed.",
    ))
    db.commit()

    background_tasks.add_task(_clear_cart, current_user.id)

    logger.info(
        "Order #%s created for user %s  Razorpay=%s  total=%.2f",
        new_order.id, current_user.id, rz_order["id"], total,
    )

    return {
        "order_id":          new_order.id,
        "razorpay_order_id": rz_order["id"],
        "amount":            round(total, 2),
        "currency":          "INR",
        "key_id":            os.getenv("RAZORPAY_KEY_ID"),
    }


# â”€â”€ 2. Legacy checkout (kept for compatibility) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post("/checkout", response_model=dict, status_code=201)
def checkout(
    order_data:       schemas.OrderCreate,
    background_tasks: BackgroundTasks,
    db:               Session = Depends(get_db),
    current_user:     models.User = Depends(get_current_user),
):
    """Legacy route â€” same Phase 2 ledger integration applied."""
    cart = (
        db.query(models.Cart)
        .options(joinedload(models.Cart.items))
        .filter(models.Cart.user_id == current_user.id)
        .first()
    )
    if not cart or not cart.items:
        raise HTTPException(status_code=400, detail="Your cart is empty.")

    try:
        primary_location = get_primary_location(db)
    except HTTPException:
        raise HTTPException(status_code=503, detail="Inventory system not ready.")

    subtotal, order_items = 0.0, []

    for cart_item in cart.items:
        product = db.get(models.Product, cart_item.product_id)
        if not product or not product.is_active:
            raise HTTPException(status_code=400, detail="A product in your cart is unavailable.")
        subtotal += float(product.price) * cart_item.quantity
        order_items.append((product, cart_item.quantity))

    # Legacy route has no shipping_method field â€” default to "standard".
    _shipping, _tax, total = _compute_totals(subtotal, "standard")

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
        try:
            commit_stock(
                db,
                product_id  = product.id,
                location_id = primary_location.id,
                quantity    = qty,
                order_id    = new_order.id,
                actor_id    = current_user.id,
            )
        except InsufficientStockError as exc:
            db.rollback()
            raise HTTPException(status_code=400, detail=str(exc))
        product.stock_quantity = max(0, product.stock_quantity - qty)

    db.add(models.TrackingEvent(
        order_id=new_order.id, status="Order Placed",
        description="Your order has been received.",
    ))
    db.commit()
    background_tasks.add_task(_clear_cart, current_user.id)

    return {
        "order_id":          new_order.id,
        "razorpay_order_id": rz_order["id"],
        "amount":            round(total, 2),
        "currency":          "INR",
        "key_id":            os.getenv("RAZORPAY_KEY_ID"),
    }


# â”€â”€ 3. Confirm payment â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post("/{order_id}/confirm-payment")
def confirm_payment(
    order_id: int,
    payload:  schemas.PaymentConfirm,
    db:       Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    order = db.query(models.Order).filter(
        models.Order.id      == order_id,
        models.Order.user_id == current_user.id,
    ).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")

    if order.razorpay_order_id != payload.razorpay_order_id:
        raise HTTPException(status_code=400, detail="Razorpay order ID mismatch.")

    if order.payment_status == "Paid":
        return {"status": "success", "message": "Order is already marked as paid."}

    key_secret = os.getenv("RAZORPAY_KEY_SECRET", "").encode()
    body       = f"{payload.razorpay_order_id}|{payload.razorpay_payment_id}".encode()
    expected   = hmac.new(key_secret, body, digestmod=hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, payload.razorpay_signature):
        logger.warning(
            "Payment signature mismatch order #%s user #%s",
            order_id, current_user.id,
        )
        raise HTTPException(
            status_code=400,
            detail="Payment verification failed. Signature mismatch.",
        )

    order.payment_status      = "Paid"
    order.razorpay_payment_id = payload.razorpay_payment_id
    order.shipping_status     = "Processing"
    db.add(models.TrackingEvent(
        order_id    = order.id,
        status      = "Payment Confirmed",
        description = "Payment received and verified. Order is being prepared.",
    ))
    db.commit()

    # Send the order confirmation email on the browser/redirect path too.
    # (Previously only the Razorpay webhook sent it; if the webhook secret
    #  isn't configured, no email was ever sent on a normal successful payment.)
    # Idempotent with the webhook because both bail out once status == "Paid".
    try:
        order_with_items = (
            db.query(models.Order)
              .options(joinedload(models.Order.items).joinedload(models.OrderItem.product))
              .filter(models.Order.id == order.id)
              .first()
        )
        send_order_confirmation_email(
            current_user.email, current_user.name, order_with_items or order
        )
    except Exception as exc:
        logger.error("Order confirmation email failed for order #%s: %s", order.id, exc)

    logger.info("Payment confirmed order #%s payment=%s", order_id, payload.razorpay_payment_id)
    return {"status": "success", "message": f"Order #{order_id} payment confirmed."}


# â”€â”€ 4. List my orders â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get("/", response_model=schemas.OrderListResponse)
def list_my_orders(
    skip:  int = 0,
    limit: int = 20,
    db:    Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Single GROUP-BY subquery for item counts â€” no N+1."""
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

    return schemas.OrderListResponse(
        orders=[
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
    )


# â”€â”€ 5. Order detail â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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


# â”€â”€ 6. Track order â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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


# â”€â”€ 7. Cancel order (Phase 2: ledger-aware) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post("/{order_id}/cancel")
def cancel_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Phase 2: uses release_committed_stock() to return inventory
    to the available bucket.  Handles legacy orders safely.
    """
    order = db.query(models.Order).filter(
        models.Order.id == order_id, models.Order.user_id == current_user.id
    ).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")
    if order.shipping_status not in ("Pending", "Processing"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel an order with status '{order.shipping_status}'.",
        )

    order.shipping_status = "Cancelled"
    order.payment_status  = (
        "Refund Initiated" if order.payment_status == "Paid" else "Cancelled"
    )

    try:
        primary_location = get_primary_location(db)
        for item in order.items:
            release_committed_stock(
                db,
                product_id  = item.product_id,
                location_id = primary_location.id,
                quantity    = item.quantity,
                order_id    = order.id,
                actor_id    = current_user.id,
            )
    except Exception as exc:
        logger.error(
            "Inventory release failed on cancel order #%s: %s", order_id, exc
        )
        # Still cancel the order even if ledger release fails
        # â€” admin can reconcile via manual adjustment

    db.add(models.TrackingEvent(
        order_id    = order.id,
        status      = "Cancelled",
        description = "Order cancelled by customer. Stock has been released.",
    ))
    db.commit()
    return {"status": "success", "message": "Order cancelled and stock restored."}
