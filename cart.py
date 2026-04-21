from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional

import models, schemas
from database import get_db
from utils import get_current_user

router = APIRouter(prefix="/cart", tags=["Shopping Cart"])


def get_user_cart(db: Session, user_id: int) -> models.Cart:
    cart = db.query(models.Cart).filter(models.Cart.user_id == user_id).first()
    if not cart:
        cart = models.Cart(user_id=user_id)
        db.add(cart)
        db.commit()
        db.refresh(cart)
    return cart


def _cart_response(db: Session, user) -> schemas.CartResponse:
    cart = get_user_cart(db, user.id)
    total = sum(item.product.price * item.quantity for item in cart.items)
    cr = schemas.CartResponse.model_validate(cart)
    cr.cart_total = total
    return cr


# ── GET CART ──────────────────────────────────────────────────────────────────
@router.get("/", response_model=schemas.CartResponse)
def view_cart(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return _cart_response(db, current_user)


# ── ADD ITEM ──────────────────────────────────────────────────────────────────
@router.post("/add", response_model=schemas.CartResponse)
def add_to_cart(
    item_data: schemas.CartItemAdd,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    product = db.query(models.Product).filter(models.Product.id == item_data.product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found.")
    if product.stock_quantity < item_data.quantity:
        raise HTTPException(status_code=400, detail="Not enough stock available.")
    cart = get_user_cart(db, current_user.id)
    existing = db.query(models.CartItem).filter(
        models.CartItem.cart_id == cart.id,
        models.CartItem.product_id == item_data.product_id,
    ).first()
    if existing:
        existing.quantity += item_data.quantity
    else:
        db.add(models.CartItem(cart_id=cart.id, product_id=item_data.product_id, quantity=item_data.quantity))
    db.commit()
    db.refresh(cart)
    return _cart_response(db, current_user)


# ── UPDATE ITEM QUANTITY (by product_id) ──────────────────────────────────────
@router.put("/update", response_model=schemas.CartResponse)
def update_cart_item(
    item_data: schemas.CartItemUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """PUT /cart/update — used by API.cart.update(productId, quantity)"""
    if item_data.quantity < 1:
        raise HTTPException(status_code=400, detail="Quantity must be at least 1.")
    cart = get_user_cart(db, current_user.id)
    item = db.query(models.CartItem).filter(
        models.CartItem.cart_id == cart.id,
        models.CartItem.product_id == item_data.product_id,
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found in cart.")
    product = db.query(models.Product).filter(models.Product.id == item_data.product_id).first()
    if product and product.stock_quantity < item_data.quantity:
        raise HTTPException(status_code=400, detail="Not enough stock available.")
    item.quantity = item_data.quantity
    db.commit()
    return _cart_response(db, current_user)


# ── REMOVE BY ITEM ID (used by CartSidebar and Cart components directly) ──────
@router.delete("/remove/{item_id}")
def remove_from_cart(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    cart = get_user_cart(db, current_user.id)
    item = db.query(models.CartItem).filter(
        models.CartItem.id == item_id,
        models.CartItem.cart_id == cart.id,
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found in your cart.")
    db.delete(item)
    db.commit()
    return {"status": "success", "message": "Item removed from cart."}


# ── CLEAR ENTIRE CART ─────────────────────────────────────────────────────────
@router.delete("/clear")
def clear_cart(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """DELETE /cart/clear — called by CheckoutPage after order is placed."""
    cart = get_user_cart(db, current_user.id)
    db.query(models.CartItem).filter(models.CartItem.cart_id == cart.id).delete()
    db.commit()
    return {"status": "success", "message": "Cart cleared."}