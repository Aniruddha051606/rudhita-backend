"""
admin.py  — Admin / Seller Dashboard

Changes in this version:
  - NEW: POST /admin/orders/{id}/refund — triggers Razorpay refund API directly
  - set_waybill() now auto-emails the customer their tracking number
  - admin_list_orders() now returns waybill field so the frontend can display it
"""

import os
import json
import uuid
import logging
from decimal import Decimal

import razorpay
from fastapi         import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm  import Session, joinedload
from sqlalchemy      import func as sqlfunc
from typing          import List, Optional

import models
import schemas
from database import get_db
from utils    import get_current_user, send_order_confirmation_email

logger = logging.getLogger("rudhita")
router = APIRouter(prefix="/admin", tags=["Admin / Seller Dashboard"])


# ── Auth dependency ───────────────────────────────────────────────────────────

def require_admin(current_user: models.User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    return current_user


# ── Audit helper ──────────────────────────────────────────────────────────────

def _audit(
    db:          Session,
    actor:       models.User,
    action:      str,
    target_type: str  = None,
    target_id:   int  = None,
    detail:      dict = None,
):
    """Persist every admin write to audit_logs. Never raises — failures are logged only."""
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


# ── 1. Dashboard ──────────────────────────────────────────────────────────────

@router.get("/dashboard")
def get_dashboard(
    db: Session = Depends(get_db),
    _:  models.User = Depends(require_admin),
):
    total_orders   = db.query(sqlfunc.count(models.Order.id)).scalar()
    total_revenue  = db.query(
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
        "totalRevenue":  total_revenue if isinstance(total_revenue, Decimal) else Decimal(str(total_revenue or 0)),
        "totalProducts": total_products,
        "recentOrders": [
            {
                "id":              o.id,
                "customer_name":   o.owner.name if o.owner else "N/A",
                "total":           float(o.total_amount),
                "shipping_status": o.shipping_status.lower() if o.shipping_status else "pending",
                "payment_status":  o.payment_status,
                "created_at":      o.created_at.isoformat(),
            }
            for o in recent_orders
        ],
    }


# ── 2. Stats ──────────────────────────────────────────────────────────────────

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


# ── 3. Products ───────────────────────────────────────────────────────────────

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


# ── 4. Orders ─────────────────────────────────────────────────────────────────

@router.get("/orders")
def admin_list_orders(
    skip:            int = Query(default=0, ge=0),
    limit:           int = Query(default=30, ge=1, le=200),
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
    return {"status": "success", "message": f"Order #{order_id} updated to '{normalised}'."}


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

    # Notify the customer their order has shipped
    try:
        user = db.query(models.User).filter(models.User.id == order.user_id).first()
        if user:
            send_order_confirmation_email(user.email, user.name, order)
    except Exception as exc:
        logger.warning("Could not send shipping notification for order #%s: %s", order_id, exc)

    return {"status": "success", "waybill": waybill}


# ── 4a. Refund ────────────────────────────────────────────────────────────────

@router.post("/orders/{order_id}/refund")
def admin_initiate_refund(
    order_id: int,
    db:       Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    """
    Calls the Razorpay Refunds API to move real money back to the customer.

    Rules:
      - Order must be Paid (payment_status == "Paid")
      - Refund can only be triggered once (idempotency: razorpay_refund_id must be null)
      - Issues a FULL refund for total_amount

    After this call:
      - order.payment_status  → "Refunded"
      - order.razorpay_refund_id is set to Razorpay's refund ID for future reference
      - A TrackingEvent is logged so the customer sees it on the tracking page

    Razorpay refunds are asynchronous — the money typically reaches the customer
    within 5–7 business days depending on their payment method.
    """
    order = db.query(models.Order).filter(models.Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found.")

    if order.payment_status != "Paid":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot refund order with payment_status='{order.payment_status}'. "
                   "Only 'Paid' orders can be refunded."
        )

    if order.razorpay_refund_id:
        raise HTTPException(
            status_code=409,
            detail=f"Refund already initiated (refund_id={order.razorpay_refund_id})."
        )

    if not order.razorpay_payment_id:
        raise HTTPException(
            status_code=400,
            detail="No Razorpay payment ID on this order — cannot issue refund."
        )

    # Call Razorpay Refunds API
    rz = _get_razorpay()
    try:
        refund = rz.payment.refund(
            order.razorpay_payment_id,
            {
                "amount": int(float(order.total_amount) * 100),  # paise
                "notes":  {
                    "reason":   "Admin-initiated refund",
                    "order_id": str(order.id),
                },
            }
        )
    except razorpay.errors.BadRequestError as exc:
        logger.error("Razorpay refund failed for order #%s: %s", order_id, exc)
        raise HTTPException(status_code=502, detail=f"Razorpay refund failed: {str(exc)}")

    refund_id             = refund.get("id", "")
    order.razorpay_refund_id = refund_id
    order.payment_status  = "Refunded"

    db.add(models.TrackingEvent(
        order_id    = order.id,
        status      = "Refunded",
        description = f"Full refund of ₹{float(order.total_amount):,.2f} initiated. "
                      f"Razorpay Refund ID: {refund_id}. "
                      "Amount typically reaches customer within 5–7 business days.",
    ))
    _audit(db, current_user, "initiate_refund", "Order", order_id, {
        "refund_id":   refund_id,
        "amount":      float(order.total_amount),
        "payment_id":  order.razorpay_payment_id,
    })
    db.commit()

    logger.info(
        "Refund initiated for order #%s by admin %s — Razorpay refund_id=%s",
        order_id, current_user.email, refund_id
    )
    return {
        "status":    "success",
        "refund_id": refund_id,
        "amount":    float(order.total_amount),
        "message":   f"Refund of ₹{float(order.total_amount):,.2f} initiated successfully.",
    }


# ── 5. Users ──────────────────────────────────────────────────────────────────

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
    logger.warning("Admin granted to user %s (%s) by admin %s", user.id, user.email, current_user.email)
    return {"status": "success", "message": f"{user.name} is now an admin."}


# ── 6. Low-stock alerts ───────────────────────────────────────────────────────

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


# ── 7. Audit log ──────────────────────────────────────────────────────────────

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