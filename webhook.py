"""
webhook.py  — Razorpay Webhook Handler

WHY THIS FILE EXISTS:
  The frontend's Razorpay handler callback (CheckoutPage.jsx) only fires when:
    - The user's browser is still open
    - Their mobile network holds through the redirect
    - The tab isn't closed before the JS executes

  In practice, ~5–10% of mobile payments in India fail to trigger the frontend
  callback even though Razorpay has already captured the money. This file is
  the server-side safety net that catches 100% of payments regardless of browser state.

SETUP IN RAZORPAY DASHBOARD:
  Settings → Webhooks → Add New Webhook
  URL:    https://your-backend.com/webhooks/razorpay
  Secret: (set RAZORPAY_WEBHOOK_SECRET in .env — must match exactly)
  Events to subscribe:
    ✓ payment.captured
    ✓ payment.failed

IMPORTANT: Set RAZORPAY_WEBHOOK_SECRET in your .env file.
"""

import os
import hmac
import json
import hashlib
import logging

from fastapi        import APIRouter, Request, HTTPException, Depends, BackgroundTasks
from sqlalchemy.orm import Session

import models
from database import get_db, SessionLocal
from utils    import send_order_confirmation_email

logger = logging.getLogger("rudhita")
router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


# ── Signature verification ────────────────────────────────────────────────────

def _verify_webhook_signature(body: bytes, signature: str) -> bool:
    """
    Razorpay signs the raw POST body with RAZORPAY_WEBHOOK_SECRET using HMAC-SHA256.
    MUST verify this — otherwise any attacker can POST a fake payment.captured event
    and get their order marked as Paid without paying.
    """
    secret = os.getenv("RAZORPAY_WEBHOOK_SECRET", "")
    if not secret:
        logger.error("RAZORPAY_WEBHOOK_SECRET is not configured — rejecting all webhook calls")
        return False
    expected = hmac.new(
        secret.encode("utf-8"),
        body,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ── Event handlers (run as background tasks with their own DB session) ────────

def _handle_payment_captured(event: dict) -> None:
    """
    Marks the order Paid and fires a confirmation email.
    Idempotent — safe to call multiple times for the same payment_id.
    The frontend's confirm_payment endpoint is the primary path; this is the fallback.
    """
    db = SessionLocal()
    try:
        payment     = event.get("payload", {}).get("payment", {}).get("entity", {})
        rz_order_id = payment.get("order_id")
        payment_id  = payment.get("id")

        if not rz_order_id or not payment_id:
            logger.warning("Webhook payment.captured missing order_id or payment_id — skipping")
            return

        order = db.query(models.Order).filter(
            models.Order.razorpay_order_id == rz_order_id
        ).first()

        if not order:
            logger.warning("Webhook: no order found for razorpay_order_id=%s", rz_order_id)
            return

        # Idempotency guard — don't overwrite a payment already confirmed by the frontend
        if order.payment_status == "Paid":
            logger.info("Webhook: order #%s already Paid — no action needed", order.id)
            return

        order.payment_status      = "Paid"
        order.razorpay_payment_id = payment_id
        order.shipping_status     = "Processing"

        db.add(models.TrackingEvent(
            order_id    = order.id,
            status      = "Payment Confirmed",
            description = "Payment captured and verified via Razorpay webhook (browser-close recovery).",
        ))
        db.commit()

        logger.info(
            "Webhook: order #%s marked Paid via payment.captured (payment_id=%s)",
            order.id, payment_id
        )

        # Send order confirmation email
        try:
            user = db.query(models.User).filter(models.User.id == order.user_id).first()
            if user:
                # Reload order with items eagerly so the email template can render them
                from sqlalchemy.orm import joinedload
                order_with_items = (
                    db.query(models.Order)
                    .options(joinedload(models.Order.items).joinedload(models.OrderItem.product))
                    .filter(models.Order.id == order.id)
                    .first()
                )
                send_order_confirmation_email(user.email, user.name, order_with_items or order)
        except Exception as exc:
            logger.error(
                "Failed to send order confirmation email for order #%s: %s",
                order.id, exc
            )

    except Exception as exc:
        logger.exception("Error handling payment.captured webhook: %s", exc)
        db.rollback()
    finally:
        db.close()


def _handle_payment_failed(event: dict) -> None:
    """
    Marks the order PaymentFailed so the admin dashboard surfaces it clearly.
    The customer can retry from the order history page.
    """
    db = SessionLocal()
    try:
        payment     = event.get("payload", {}).get("payment", {}).get("entity", {})
        rz_order_id = payment.get("order_id")
        error_desc  = payment.get("error_description", "Unknown error")
        error_code  = payment.get("error_code", "")

        if not rz_order_id:
            return

        order = db.query(models.Order).filter(
            models.Order.razorpay_order_id == rz_order_id
        ).first()

        if not order:
            logger.warning("Webhook payment.failed: no order found for razorpay_order_id=%s", rz_order_id)
            return

        # Don't overwrite a successfully paid order (race between success and failure events)
        if order.payment_status == "Paid":
            return

        order.payment_status = "Failed"
        db.add(models.TrackingEvent(
            order_id    = order.id,
            status      = "Payment Failed",
            description = f"Payment failed. Reason: {error_desc} (code: {error_code}). "
                          "You can retry payment from your order history.",
        ))
        db.commit()

        logger.warning(
            "Webhook: payment failed for order #%s — %s (%s)",
            order.id, error_desc, error_code
        )

    except Exception as exc:
        logger.exception("Error handling payment.failed webhook: %s", exc)
        db.rollback()
    finally:
        db.close()


# ── Webhook endpoint ──────────────────────────────────────────────────────────

@router.post("/razorpay")
async def razorpay_webhook(
    request:          Request,
    background_tasks: BackgroundTasks,
):
    """
    Receives signed events from Razorpay and dispatches them to background handlers.

    CRITICAL: We always return HTTP 200 to Razorpay, even on internal errors.
    Razorpay retries any non-2xx response up to 8 times over 24 hours.
    Returning 500 would cause duplicate processing — all errors are logged instead.
    """
    body      = await request.body()
    signature = request.headers.get("X-Razorpay-Signature", "")

    # ── Step 1: Verify the signature before doing anything ─────────────────
    if not _verify_webhook_signature(body, signature):
        logger.warning(
            "Razorpay webhook: INVALID signature from %s — rejected",
            request.client.host if request.client else "unknown"
        )
        # Return 400 for invalid signature — this is intentional, not an internal error.
        # Razorpay will NOT retry 4xx responses.
        raise HTTPException(status_code=400, detail="Invalid webhook signature.")

    # ── Step 2: Parse and dispatch ─────────────────────────────────────────
    try:
        event      = json.loads(body)
        event_type = event.get("event", "")
        event_id   = event.get("id", "unknown")

        logger.info("Razorpay webhook received: event=%s id=%s", event_type, event_id)

        if event_type == "payment.captured":
            background_tasks.add_task(_handle_payment_captured, event)

        elif event_type == "payment.failed":
            background_tasks.add_task(_handle_payment_failed, event)

        else:
            # Log unhandled events but don't error — Razorpay sends many event types
            logger.debug("Webhook: unhandled event type '%s' — ignored", event_type)

    except json.JSONDecodeError as exc:
        logger.error("Webhook: could not parse JSON body: %s", exc)
        # Still return 200 so Razorpay doesn't retry a malformed payload
    except Exception as exc:
        logger.exception("Webhook: unexpected error during dispatch: %s", exc)
        # Return 200 — log and investigate, never let Razorpay retry indefinitely

    return {"status": "received"}