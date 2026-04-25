"""
utils.py  Ã¢â‚¬â€  Auth Utilities (PATCHED)

Changes from audit:
  - hash_otp()            : OTPs now stored as HMAC-SHA256, never plain text
  - send_otp_email()      : Real SMTP transport; print() only in dev mode
  - create_access_token() : Includes 'jti' claim so tokens can be revoked
  - create_refresh_token(): Opaque random token stored in DB
  - get_current_user()    : Checks TokenBlocklist before trusting a token
"""

import os
import hmac
import uuid
import secrets
import hashlib
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from database import get_db

logger = logging.getLogger("rudhita")

# Ã¢â€â‚¬Ã¢â€â‚¬ Secrets & config Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY is not set. Add it to your .env file.")

ALGORITHM                  = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS   = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))

# Ã¢â€â‚¬Ã¢â€â‚¬ Password hashing Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# Ã¢â€â‚¬Ã¢â€â‚¬ OTP helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
def hash_otp(otp: str) -> str:
    """
    Returns an HMAC-SHA256 hex digest of the OTP.
    Stored in the DB instead of plain text so a DB leak doesn't expose codes.
    """
    # BUG 8 FIX: use digestmod= keyword arg â€” positional is deprecated and fails in some envs
    return hmac.new(
        SECRET_KEY.encode("utf-8"),
        otp.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def verify_otp_hash(plain_otp: str, stored_hash: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    return hmac.compare_digest(hash_otp(plain_otp), stored_hash)


# Ã¢â€â‚¬Ã¢â€â‚¬ Email Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
def send_otp_email(to_email: str, otp_code: str) -> None:
    """
    Sends the OTP via SMTP.
    Requires in .env:
        SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASS, FROM_EMAIL

    In development (SMTP_HOST not set), falls back to a WARNING log line only.
    Never prints the OTP to stdout in production.
    """
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    from_email = os.getenv("FROM_EMAIL", smtp_user)

    if not smtp_host or not smtp_user:
        # Development only Ã¢â‚¬â€ never reaches this branch in production
        logger.warning("[DEV] OTP for %s => %s  (set SMTP_HOST to send real emails)", to_email, otp_code)
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your Rudhita Verification Code"
    msg["From"]    = from_email
    msg["To"]      = to_email

    text = (
        f"Your Rudhita verification code is: {otp_code}\n"
        f"It expires in 10 minutes.\n"
        f"If you did not request this, please ignore this email."
    )
    html = f"""
    <html><body style="font-family:sans-serif;max-width:480px;margin:auto">
      <h2 style="color:#1a1a1a">Your Rudhita OTP</h2>
      <p style="font-size:32px;letter-spacing:6px;font-weight:bold;color:#333">{otp_code}</p>
      <p style="color:#555">This code expires in <strong>10 minutes</strong>.</p>
      <p style="color:#999;font-size:12px">If you didn't request this, ignore this email.</p>
    </body></html>
    """
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_email, [to_email], msg.as_string())
        logger.info("OTP email dispatched to %s", to_email)
    except smtplib.SMTPException as exc:
        logger.error("SMTP error sending to %s: %s", to_email, exc)
        raise HTTPException(
            status_code=503,
            detail="Email service temporarily unavailable. Please try again shortly.",
        )


# Ã¢â€â‚¬Ã¢â€â‚¬ JWT access token Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
def create_access_token(data: dict) -> str:
    """
    Generates a signed JWT.
    Includes 'jti' (JWT ID) so individual tokens can be blocklisted on logout.
    """
    to_encode = data.copy()
    expire    = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jti       = str(uuid.uuid4())
    to_encode.update({"exp": expire, "jti": jti})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Ã¢â€â‚¬Ã¢â€â‚¬ Refresh token Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
def create_refresh_token() -> tuple[str, datetime]:
    """
    Returns (opaque_token_string, expiry_datetime).
    The caller must persist the token in the RefreshToken table.
    """
    token      = secrets.token_urlsafe(48)
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return token, expires_at


# Ã¢â€â‚¬Ã¢â€â‚¬ Auth dependency Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    """
    FastAPI dependency Ã¢â‚¬â€ decodes the JWT, checks the blocklist,
    and returns the authenticated User object.
    """
    import models  # local import to avoid circular dependency

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str  = payload.get("sub")
        user_id: int = payload.get("id")
        jti: str    = payload.get("jti")
        if not email or not user_id or not jti:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    # FIX: check if this specific token was revoked (logout)
    blocked = db.query(models.TokenBlocklist).filter(
        models.TokenBlocklist.jti == jti
    ).first()
    if blocked:
        raise credentials_exception

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None or not user.is_verified:
        raise credentials_exception

    return user


def send_order_confirmation_email(to_email: str, customer_name: str, order) -> None:
    """
    Sends a post-payment order confirmation email.
    Called from:
      - orders.py confirm_payment() (browser redirect path)
      - webhook.py payment.captured handler (server-side safety net)
      - admin.py set_waybill() (shipping notification)

    Falls back to a log warning in development if SMTP is not configured.
    """
    smtp_host  = os.getenv("SMTP_HOST")
    smtp_port  = int(os.getenv("SMTP_PORT", "587"))
    smtp_user  = os.getenv("SMTP_USER")
    smtp_pass  = os.getenv("SMTP_PASS")
    from_email = os.getenv("FROM_EMAIL", smtp_user)

    if not smtp_host or not smtp_user:
        logger.warning(
            "[DEV] Order confirmation for %s, order #%s (set SMTP_HOST to send real emails)",
            to_email, getattr(order, "id", "?")
        )
        return

    items_html = "".join(
        "<tr>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #eee'>{item.product.name if item.product else 'Product'}</td>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #eee;text-align:center'>{item.quantity}</td>"
        f"<td style='padding:8px 12px;border-bottom:1px solid #eee;text-align:right'>\u20b9{float(item.price_at_purchase or 0):,.2f}</td>"
        "</tr>"
        for item in (getattr(order, "items", None) or [])
    )

    order_id     = getattr(order, "id", "?")
    total_amount = float(getattr(order, "total_amount", 0) or 0)
    shipping_addr = getattr(order, "shipping_address", "On file")

    html = f"""
    <html><body style="font-family:sans-serif;max-width:600px;margin:auto;color:#18100C">
      <div style="background:#A85538;padding:24px 32px">
        <h1 style="color:#F5EFE6;margin:0;font-size:24px;font-family:Georgia,serif">Rudhita</h1>
      </div>
      <div style="padding:32px">
        <h2 style="font-family:Georgia,serif;font-weight:normal">Order Confirmed, {customer_name}!</h2>
        <p style="color:#555">Thank you for your purchase. Order <strong>#{order_id}</strong> is being prepared.</p>
        <table style="width:100%;border-collapse:collapse;margin:20px 0">
          <thead>
            <tr style="background:#F5EFE6">
              <th style="padding:8px 12px;text-align:left;font-size:12px;text-transform:uppercase">Item</th>
              <th style="padding:8px 12px;text-align:center;font-size:12px;text-transform:uppercase">Qty</th>
              <th style="padding:8px 12px;text-align:right;font-size:12px;text-transform:uppercase">Price</th>
            </tr>
          </thead>
          <tbody>{items_html}</tbody>
          <tfoot>
            <tr>
              <td colspan="2" style="padding:12px;font-weight:bold;text-align:right">Total</td>
              <td style="padding:12px;font-weight:bold;text-align:right">\u20b9{total_amount:,.2f}</td>
            </tr>
          </tfoot>
        </table>
        <p style="color:#555"><strong>Shipping to:</strong><br>{shipping_addr}</p>
        <p style="color:#999;font-size:12px;margin-top:32px">
          Track your order: rudhita.vercel.app/order/{order_id}/tracking
        </p>
      </div>
    </body></html>
    """

    plain = (
        f"Order #{order_id} confirmed — thank you, {customer_name}!\n"
        f"Total: \u20b9{total_amount:,.2f}\n"
        f"Track: rudhita.vercel.app/order/{order_id}/tracking"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Order #{order_id} Confirmed — Rudhita"
    msg["From"]    = from_email
    msg["To"]      = to_email
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html,  "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_email, [to_email], msg.as_string())
        logger.info("Order confirmation email sent to %s for order #%s", to_email, order_id)
    except smtplib.SMTPException as exc:
        # Non-fatal — order is already paid; email failure should NOT block the user
        logger.error("SMTP error sending order confirmation to %s: %s", to_email, exc)
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def send_order_confirmation_email(to_email: str, user_name: str, order):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = os.getenv("SMTP_PORT", 587)
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    from_email = os.getenv("FROM_EMAIL")

    # If email isn't set up yet, silently skip so it doesn't crash the server
    if not all([smtp_host, smtp_user, smtp_pass, from_email]):
        print(f"Skipping email to {to_email}: SMTP not fully configured in .env")
        return

    subject = f"Your Rudhita Order Confirmation - #{order.id}"
    body = f"""Hello {user_name},

Thank you for shopping with Rudhita! Your order #{order.id} has been successfully placed.

Total Amount: ₹{order.total_amount}
Payment Status: {order.payment_status}

We will notify you as soon as your order ships.

Best regards,
The Rudhita Team
"""

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_host, int(smtp_port))
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f"Failed to send order confirmation email: {e}")