"""
schemas.py  —  Pydantic Schemas (PATCHED)

Changes from audit:
  - UserCreate:     password min 8 chars, name min 2 chars (schema-level, not just route)
  - CartItemAdd:    quantity capped at 1-50
  - ProductBase:    price must be > 0, stock_quantity >= 0
  - PaymentConfirm: new schema that requires all three Razorpay fields for signature check
  - Money fields:   use Decimal so numeric precision is preserved end-to-end
"""

from decimal import Decimal
from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator
from typing import Optional, List
from datetime import datetime


# ═══════════════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════════════

class UserCreate(BaseModel):
    name:     str      = Field(min_length=2, max_length=100)
    email:    EmailStr
    password: str      = Field(min_length=8, max_length=128,
                               description="At least 8 characters")
    phone: Optional[str] = Field(default=None, max_length=20)


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str


class OTPVerify(BaseModel):
    email: EmailStr
    otp:   str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class ResendOTP(BaseModel):
    email: EmailStr


class UserResponse(BaseModel):
    id:         int
    name:       str
    email:      EmailStr
    phone:      Optional[str] = None
    is_verified: bool                # FIX: was int
    is_admin:   bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class UserProfileUpdate(BaseModel):
    name:     Optional[str] = Field(default=None, min_length=2, max_length=100)
    phone:    Optional[str] = Field(default=None, max_length=20)
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)


class Token(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str


class RefreshRequest(BaseModel):
    refresh_token: str


# ═══════════════════════════════════════════════════════════════════════
# ADDRESS
# ═══════════════════════════════════════════════════════════════════════

class AddressCreate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name:       str  = Field(min_length=2, max_length=150)
    phone:      str  = Field(min_length=7, max_length=20)
    street:     str  = Field(min_length=5, max_length=500)
    city:       str  = Field(min_length=2, max_length=100)
    state:      str  = Field(min_length=2, max_length=100)
    pincode:    str  = Field(min_length=6, max_length=10, pattern=r"^\d{6}$")
    is_default: bool = Field(default=False, alias="isDefault")


class AddressUpdate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name:       Optional[str]  = Field(default=None, min_length=2, max_length=150)
    phone:      Optional[str]  = Field(default=None, max_length=20)
    street:     Optional[str]  = None
    city:       Optional[str]  = None
    state:      Optional[str]  = None
    pincode:    Optional[str]  = Field(default=None, pattern=r"^\d{6}$")
    is_default: Optional[bool] = Field(default=None, alias="isDefault")


class AddressResponse(BaseModel):
    id:         int
    name:       str
    phone:      str
    street:     str
    city:       str
    state:      str
    pincode:    str
    is_default: bool = Field(serialization_alias="isDefault")
    created_at: datetime
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# ═══════════════════════════════════════════════════════════════════════
# PRODUCT
# ═══════════════════════════════════════════════════════════════════════

class ProductBase(BaseModel):
    sku:            str
    name:           str     = Field(min_length=2, max_length=200)
    description:    Optional[str] = None
    category:       Optional[str] = None
    price:          Decimal = Field(gt=0, decimal_places=2)     # FIX: > 0, was float
    original_price: Optional[Decimal] = Field(default=None, gt=0, decimal_places=2)
    stock_quantity: int     = Field(default=0, ge=0)
    weight_grams:   int     = Field(default=0, ge=0)
    image_url:      Optional[str] = Field(default=None, max_length=500)

    @field_validator("original_price")
    @classmethod
    def original_must_exceed_price(cls, v, info):
        if v is not None and "price" in info.data and v <= info.data["price"]:
            raise ValueError("original_price must be greater than price to show a discount")
        return v


class ProductCreate(ProductBase):
    pass


class ProductAdminCreate(BaseModel):
    """Used by the admin form — SKU is auto-generated if not supplied."""
    name:           str            = Field(min_length=2, max_length=200)
    description:    Optional[str] = None
    category:       str
    price:          Decimal        = Field(gt=0, decimal_places=2)
    original_price: Optional[Decimal] = Field(default=None, alias="originalPrice", gt=0)
    stock_quantity: int            = Field(default=0, ge=0, alias="stock")
    weight_grams:   int            = Field(default=0, ge=0)
    image_url:      Optional[str] = None
    sku:            Optional[str] = None
    model_config = ConfigDict(populate_by_name=True)


class ProductUpdate(BaseModel):
    name:           Optional[str]     = None
    description:    Optional[str]     = None
    category:       Optional[str]     = None
    price:          Optional[Decimal] = Field(default=None, gt=0)
    original_price: Optional[Decimal] = Field(default=None, gt=0)
    stock_quantity: Optional[int]     = Field(default=None, ge=0)
    weight_grams:   Optional[int]     = Field(default=None, ge=0)
    image_url:      Optional[str]     = None
    is_active:      Optional[bool]    = None


class ProductResponse(ProductBase):
    id:               int
    is_active:        bool
    created_at:       datetime
    discount_percent: Optional[int] = None
    model_config = ConfigDict(from_attributes=True)


class ProductListResponse(BaseModel):
    products: List[ProductResponse]
    total:    Optional[int] = None   # FIX: added so paginated endpoints can return count
    skip:     Optional[int] = None
    limit:    Optional[int] = None


# ═══════════════════════════════════════════════════════════════════════
# CART
# ═══════════════════════════════════════════════════════════════════════

class CartItemAdd(BaseModel):
    product_id: int
    quantity:   int = Field(default=1, ge=1, le=50)   # FIX: was uncapped


class CartItemUpdate(BaseModel):
    product_id: int
    quantity:   int = Field(ge=1, le=50)


class CartItemResponse(BaseModel):
    id:       int
    quantity: int
    product:  ProductResponse
    model_config = ConfigDict(from_attributes=True)


class CartResponse(BaseModel):
    id:         int
    user_id:    int
    items:      List[CartItemResponse] = []
    cart_total: Decimal = Decimal("0.00")             # FIX: was float
    model_config = ConfigDict(from_attributes=True)


# ═══════════════════════════════════════════════════════════════════════
# ORDERS
# ═══════════════════════════════════════════════════════════════════════

class OrderCreate(BaseModel):
    shipping_address: str


class CheckoutAddress(BaseModel):
    name:    str = Field(min_length=2, max_length=150)
    phone:   str = Field(min_length=7, max_length=20)
    street:  str = Field(min_length=5)
    city:    str = Field(min_length=2, max_length=100)
    state:   str = Field(min_length=2, max_length=100)
    pincode: str = Field(min_length=6, max_length=10, pattern=r"^\d{6}$")


class FrontendOrderCreate(BaseModel):
    address:        CheckoutAddress
    shipping_method: str = "standard"
    payment_method:  str = "razorpay"
    # NOTE: 'total' from frontend is intentionally ignored — backend recalculates from DB
    total: Optional[Decimal] = None


# ── FIX: New schema for payment confirmation that requires all 3 Razorpay fields ──
class PaymentConfirm(BaseModel):
    """
    All three fields are required for Razorpay HMAC-SHA256 signature verification.
    Without this, anyone can mark an order as paid for free.
    """
    razorpay_order_id:   str = Field(min_length=1)
    razorpay_payment_id: str = Field(min_length=1)
    razorpay_signature:  str = Field(min_length=1)


class PaymentStatusUpdate(BaseModel):
    """Legacy — kept only for the shipping address admin patch."""
    payment_status:      str
    razorpay_payment_id: Optional[str] = None
    delhivery_waybill:   Optional[str] = None


class OrderItemResponse(BaseModel):
    id:                int
    quantity:          int
    price_at_purchase: Decimal
    product:           ProductResponse
    model_config = ConfigDict(from_attributes=True)


class TrackingEventResponse(BaseModel):
    id:          int
    status:      str
    location:    Optional[str] = None
    description: Optional[str] = None
    created_at:  datetime
    model_config = ConfigDict(from_attributes=True)


class OrderResponse(BaseModel):
    id:                   int
    user_id:              int
    total_amount:         Decimal
    payment_status:       str
    shipping_status:      str
    razorpay_order_id:    Optional[str] = None
    delhivery_waybill:    Optional[str] = None
    shipping_address:     str
    created_at:           datetime
    updated_at:           datetime
    items:                List[OrderItemResponse] = []
    tracking_events:      List[TrackingEventResponse] = []
    model_config = ConfigDict(from_attributes=True)


class OrderSummaryResponse(BaseModel):
    id:              int
    total_amount:    Decimal
    payment_status:  str
    shipping_status: str
    item_count:      int
    created_at:      datetime
    model_config = ConfigDict(from_attributes=True)


class OrderListResponse(BaseModel):
    orders: List[OrderSummaryResponse]


class TrackingResponse(BaseModel):
    order_id:       int
    shipping_status: str
    waybill:        Optional[str] = None
    events:         List[TrackingEventResponse] = []


# ═══════════════════════════════════════════════════════════════════════
# ADMIN / SELLER DASHBOARD
# ═══════════════════════════════════════════════════════════════════════

class OrderStatusUpdate(BaseModel):
    shipping_status: str
    location:        Optional[str] = None
    description:     Optional[str] = None


class AdminOrderUpdate(BaseModel):
    status: str


class DashboardStats(BaseModel):
    total_orders:      int
    pending_orders:    int
    shipped_orders:    int
    delivered_orders:  int
    total_revenue:     Decimal
    total_products:    int
    low_stock_products: int
    total_users:       int


class AdminDashboardResponse(BaseModel):
    totalOrders:   int
    totalRevenue:  Decimal
    totalProducts: int
    recentOrders:  list


class ProductStockAlert(BaseModel):
    id:             int
    sku:            str
    name:           str
    stock_quantity: int
    model_config = ConfigDict(from_attributes=True)


class AdminUserResponse(BaseModel):
    id:         int
    name:       str
    email:      str
    phone:      Optional[str] = None
    is_verified: bool
    is_admin:   bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
