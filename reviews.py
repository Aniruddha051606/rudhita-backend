"""
reviews.py  –  Product Reviews Router  |  PHASE 3
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func as sqlfunc

import models
import schemas
import utils
from database import get_db

router = APIRouter(prefix="/products", tags=["Reviews"])


@router.post(
    "/{product_id}/reviews",
    response_model=schemas.ReviewResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_review(
    product_id: int,
    data: schemas.ReviewCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user),
):
    product = db.query(models.Product).filter(
        models.Product.id == product_id,
        models.Product.is_active == True,
    ).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found.")

    existing = db.query(models.ProductReview).filter(
        models.ProductReview.user_id   == current_user.id,
        models.ProductReview.product_id == product_id,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="You have already reviewed this product.")

    # Verified badge if the user has a paid order containing this product
    has_purchase = (
        db.query(models.OrderItem)
        .join(models.Order)
        .filter(
            models.Order.user_id          == current_user.id,
            models.OrderItem.product_id   == product_id,
            models.Order.payment_status   == "Paid",
        )
        .first()
    )

    review = models.ProductReview(
        user_id     = current_user.id,
        product_id  = product_id,
        rating      = data.rating,
        title       = data.title,
        body        = data.body,
        is_verified = bool(has_purchase),
    )
    db.add(review)
    db.commit()
    db.refresh(review)
    return review


@router.get("/{product_id}/reviews", response_model=list[schemas.ReviewResponse])
def get_reviews(
    product_id: int,
    skip:  int = 0,
    limit: int = 20,
    db: Session = Depends(get_db),
):
    product = db.query(models.Product).filter(models.Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found.")

    rows = (
        db.query(models.ProductReview)
        .options(joinedload(models.ProductReview.user))
        .filter(models.ProductReview.product_id == product_id)
        .order_by(models.ProductReview.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return [
        {
            "id":           r.id,
            "product_id":   r.product_id,
            "user_id":      r.user_id,
            "rating":       r.rating,
            "title":        r.title,
            "body":         r.body,
            "is_verified":  r.is_verified,
            "created_at":   r.created_at,
            "author_name":  r.user.name       if r.user else None,
            "author_avatar": r.user.avatar_url if r.user else None,
        }
        for r in rows
    ]


@router.get("/{product_id}/reviews/summary", response_model=schemas.ProductRatingSummary)
def get_rating_summary(product_id: int, db: Session = Depends(get_db)):
    product = db.query(models.Product).filter(models.Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found.")

    rows = (
        db.query(
            models.ProductReview.rating,
            sqlfunc.count(models.ProductReview.id).label("cnt"),
        )
        .filter(models.ProductReview.product_id == product_id)
        .group_by(models.ProductReview.rating)
        .all()
    )

    distribution = {r: 0 for r in range(1, 6)}
    total = 0
    rating_sum = 0
    for rating, cnt in rows:
        distribution[rating] = cnt
        total      += cnt
        rating_sum += rating * cnt

    return schemas.ProductRatingSummary(
        product_id     = product_id,
        average_rating = round(rating_sum / total, 2) if total else 0.0,
        review_count   = total,
        distribution   = distribution,
    )


@router.delete(
    "/{product_id}/reviews/{review_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_review(
    product_id: int,
    review_id:  int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(utils.get_current_user),
):
    review = db.query(models.ProductReview).filter(
        models.ProductReview.id         == review_id,
        models.ProductReview.product_id == product_id,
    ).first()
    if not review:
        raise HTTPException(status_code=404, detail="Review not found.")
    if review.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to delete this review.")
    db.delete(review)
    db.commit()
