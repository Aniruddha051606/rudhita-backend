"""
models.py  —  Rudhita Database Models (PATCHED)

Changes from audit:
  - Float -> Numeric(10, 2) for ALL money columns (prevents precision loss on totals)
  - User.is_verified: Integer -> Boolean
  - Added RefreshToken  (for /auth/refresh flow)
  - Added TokenBlocklist (for /auth/logout token revocation)
  - Added AuditLog      (admin action trail)

MIGRATION NOTE:
  If you have an existing database, run these SQL statements before deploying:
    ALTER TABLE products
        ALTER COLUMN price TYPE NUMERIC(10,2),
        ALTER COLUMN original_price TYPE NUMERIC(10,2);
    ALTER TABLE orders
        ALTER COLUMN total_amount TYPE NUMERIC(10,2);
    ALTER TABLE order_items
        ALTER COLUMN price_at_purchase TYPE NUMERIC(10,2);
    ALTER TABLE users
        ALTER COLUMN is_verified TYPE BOOLEAN USING (is_verified::boolean);
  Then run:  alembic upgrade head  (after setting up Alembic)
"""

from sqlalchemy import (
    Column, Integer, String, Float, ForeignKey,
    DateTime, Text, Boolean, Index, Numeric
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base


class User(Base):
    __tablename__ = "users"
    id             = Column(Integer, primary_key=True, index=True)
    name           = Column(String(100), nullable=False)
    email          = Column(String(150), unique=True, nullable=False, index=True)
    password_hash  = Column(String(255), nullable=False)            # FIX: was nullable=True
    phone          = Column(String(20))
    is_verified    = Column(Boolean, default=False, nullable=False)  # FIX: was Integer
    is_admin       = Column(Boolean, default=False)
    created_at     = Column(DateTime(timezone=True), server_default=func.now())
    orders         = relationship("Order", back_populates="owner", lazy="select")
    cart           = relationship("Cart", back_populates="user", uselist=False)
    addresses      = relationship("Address", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")


class Address(Base):
    __tablename__ = "addresses"
    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name       = Column(String(150), nullable=False)
    phone      = Column(String(20), nullable=False)
    street     = Column(Text, nullable=False)
    city       = Column(String(100), nullable=False)
    state      = Column(String(100), nullable=False)
    pincode    = Column(String(10), nullable=False)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user       = relationship("User", back_populates="addresses")


class Product(Base):
    __tablename__ = "products"
    id             = Column(Integer, primary_key=True, index=True)
    sku            = Column(String(50), unique=True, nullable=False, index=True)
    name           = Column(String(200), nullable=False)
    description    = Column(Text)
    category       = Column(String(100), index=True)
    price          = Column(Numeric(10, 2), nullable=False)          # FIX: was Float
    original_price = Column(Numeric(10, 2))                          # FIX: was Float
    stock_quantity = Column(Integer, default=0, nullable=False)
    weight_grams   = Column(Integer, default=0, nullable=False)
    image_url      = Column(String(500))
    is_active      = Column(Boolean, default=True)
    created_at     = Column(DateTime(timezone=True), server_default=func.now())
    __table_args__  = (Index("ix_products_category_price", "category", "price"),)


class Order(Base):
    __tablename__ = "orders"
    id                  = Column(Integer, primary_key=True, index=True)
    user_id             = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    total_amount        = Column(Numeric(10, 2), nullable=False)     # FIX: was Float
    payment_status      = Column(String(50), default="Pending", index=True)
    shipping_status     = Column(String(50), default="Pending", index=True)
    razorpay_order_id   = Column(String(100), index=True)
    razorpay_payment_id = Column(String(100))
    delhivery_waybill   = Column(String(100), index=True)
    shipping_address    = Column(Text, nullable=False)
    created_at          = Column(DateTime(timezone=True), server_default=func.now())
    updated_at          = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    owner           = relationship("User", back_populates="orders")
    items           = relationship("OrderItem", back_populates="order", cascade="all, delete-orphan")
    tracking_events = relationship(
        "TrackingEvent", back_populates="order",
        order_by="TrackingEvent.created_at", cascade="all, delete-orphan"
    )


class OrderItem(Base):
    __tablename__ = "order_items"
    id                = Column(Integer, primary_key=True, index=True)
    order_id          = Column(Integer, ForeignKey("orders.id"), nullable=False, index=True)
    product_id        = Column(Integer, ForeignKey("products.id"), nullable=False)
    quantity          = Column(Integer, nullable=False, default=1)
    price_at_purchase = Column(Numeric(10, 2), nullable=False)       # FIX: was Float
    order   = relationship("Order", back_populates="items")
    product = relationship("Product")


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
    otp_code   = Column(String(64), nullable=False)  # FIX: stores HMAC hash now, needs 64 chars
    expires_at = Column(DateTime(timezone=True), nullable=False)


class Cart(Base):
    __tablename__ = "carts"
    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user  = relationship("User", back_populates="cart")
    items = relationship("CartItem", back_populates="cart", cascade="all, delete-orphan")


class CartItem(Base):
    __tablename__ = "cart_items"
    id         = Column(Integer, primary_key=True, index=True)
    cart_id    = Column(Integer, ForeignKey("carts.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    quantity   = Column(Integer, default=1, nullable=False)
    cart    = relationship("Cart", back_populates="items")
    product = relationship("Product")


# ── NEW: Refresh token storage (one row per active session) ──────────────────
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token      = Column(String(128), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user       = relationship("User", back_populates="refresh_tokens")


# ── NEW: Token blocklist (revoked JTIs so logout actually works) ─────────────
class TokenBlocklist(Base):
    __tablename__ = "token_blocklist"
    id         = Column(Integer, primary_key=True, index=True)
    jti        = Column(String(64), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)  # for cleanup job


# ── NEW: Admin audit log ─────────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_logs"
    id          = Column(Integer, primary_key=True, index=True)
    actor_id    = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    action      = Column(String(100), nullable=False)   # e.g. "make_admin", "update_order_status"
    target_type = Column(String(50))                    # e.g. "User", "Order"
    target_id   = Column(Integer)
    detail      = Column(Text)                          # JSON string for extra context
    created_at  = Column(DateTime(timezone=True), server_default=func.now(), index=True)
