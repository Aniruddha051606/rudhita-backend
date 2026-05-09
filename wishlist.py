"""
wishlist.py  –  Wishlist Router  |  PHASE 3
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload

import models
import schemas
import utils
from database import get_db

router = APIRouter(prefix="/wishlist", tags=["Wishlist"])


class WishlistToggleRequest(BaseModel):
    product_id: int


@router.get("", response_model=list[schemas.WishlistItemResponse])
def get_wishlist(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user),
):
    return (
        db.query(models.WishlistItem)
        .options(joinedload(models.WishlistItem.product))
        .filter(models.WishlistItem.user_id == current_user.id)
        .all()
    )


@router.post("/toggle", status_code=status.HTTP_200_OK)
def toggle_wishlist(
    payload: WishlistToggleRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user),
):
    product = db.query(models.Product).filter(
        models.Product.id == payload.product_id,
        models.Product.is_active == True,
    ).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found.")

    existing = db.query(models.WishlistItem).filter(
        models.WishlistItem.user_id    == current_user.id,
        models.WishlistItem.product_id == payload.product_id,
    ).first()

    if existing:
        db.delete(existing)
        db.commit()
        return {"action": "removed", "product_id": payload.product_id}

    db.add(models.WishlistItem(user_id=current_user.id, product_id=payload.product_id))
    db.commit()
    return {"action": "added", "product_id": payload.product_id}
