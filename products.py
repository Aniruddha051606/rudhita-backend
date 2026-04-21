"""
products.py  —  Product Routes (PATCHED)

Changes from audit:
  - get_by_category(): added skip/limit with Query(le=100) hard cap — was unbounded
  - search_products(): added skip, total count returned alongside results
  - Both endpoints now return { products, total, skip, limit } for proper frontend pagination
"""

import uuid
from fastapi           import APIRouter, Depends, HTTPException, Query
from sqlalchemy        import func
from sqlalchemy.orm    import Session
from typing            import List, Optional

import models
import schemas
from database import get_db
from utils    import get_current_user

router = APIRouter(prefix="/products", tags=["Products"])


def _build_response(p) -> schemas.ProductResponse:
    pr = schemas.ProductResponse.model_validate(p)
    if p.original_price and p.original_price > p.price:
        pr.discount_percent = int((1 - float(p.price) / float(p.original_price)) * 100)
    return pr


# ── 1. Create product (admin only) ────────────────────────────────────────────

@router.post("/", response_model=schemas.ProductResponse, status_code=201)
def create_product(
    product: schemas.ProductCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required.")
    if db.query(models.Product).filter(models.Product.sku == product.sku).first():
        raise HTTPException(status_code=400, detail="A product with this SKU already exists.")
    new_product = models.Product(**product.model_dump())
    db.add(new_product)
    db.commit()
    db.refresh(new_product)
    return _build_response(new_product)


# ── 2. Catalogue ──────────────────────────────────────────────────────────────

@router.get("/", response_model=schemas.ProductListResponse)
def get_products(
    skip:     int           = Query(default=0, ge=0),
    limit:    int           = Query(default=40, ge=1, le=100),  # hard cap
    category: Optional[str] = None,
    search:   Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(models.Product).filter(models.Product.is_active == True)
    if category:
        q = q.filter(models.Product.category == category)
    if search:
        q = q.filter(
            models.Product.name.ilike(f"%{search}%") |
            models.Product.description.ilike(f"%{search}%")
        )
    total    = q.with_entities(func.count(models.Product.id)).scalar()
    products = q.order_by(models.Product.created_at.desc()).offset(skip).limit(limit).all()
    return schemas.ProductListResponse(
        products=[_build_response(p) for p in products],
        total=total, skip=skip, limit=limit,
    )


# ── 3. Featured ───────────────────────────────────────────────────────────────

@router.get("/featured", response_model=List[schemas.ProductResponse])
def get_featured_products(
    limit: int = Query(default=8, ge=1, le=40),
    db: Session = Depends(get_db),
):
    products = (
        db.query(models.Product)
        .filter(models.Product.is_active == True)
        .order_by(
            (models.Product.original_price > models.Product.price).desc(),
            models.Product.created_at.desc(),
        )
        .limit(limit).all()
    )
    return [_build_response(p) for p in products]


# ── 4. Search ─────────────────────────────────────────────────────────────────

@router.get("/search", response_model=schemas.ProductListResponse)
def search_products(
    q:     str = Query(default="", max_length=100),
    skip:  int = Query(default=0, ge=0),
    limit: int = Query(default=40, ge=1, le=100),   # FIX: was hardcoded 40 with no total
    db: Session = Depends(get_db),
):
    base = (
        db.query(models.Product)
        .filter(
            models.Product.is_active == True,
            models.Product.name.ilike(f"%{q}%") |
            models.Product.description.ilike(f"%{q}%"),
        )
    )
    total    = base.with_entities(func.count(models.Product.id)).scalar()
    products = base.order_by(models.Product.created_at.desc()).offset(skip).limit(limit).all()
    return schemas.ProductListResponse(
        products=[_build_response(p) for p in products],
        total=total, skip=skip, limit=limit,
    )


# ── 5. By category ────────────────────────────────────────────────────────────

@router.get("/category/{category}", response_model=schemas.ProductListResponse)
def get_by_category(
    category: str,
    skip:     int = Query(default=0, ge=0),
    limit:    int = Query(default=40, ge=1, le=100),    # FIX: was .all() with NO limit at all
    db: Session = Depends(get_db),
):
    """
    FIX: Previously fetched every row in the category with no LIMIT.
         With 10,000 products this would return a 10 MB+ JSON payload and OOM the server.
         Now paginated with a hard cap of 100 per page.
    """
    base = (
        db.query(models.Product)
        .filter(models.Product.is_active == True, models.Product.category == category)
    )
    total    = base.with_entities(func.count(models.Product.id)).scalar()
    products = base.order_by(models.Product.created_at.desc()).offset(skip).limit(limit).all()
    return schemas.ProductListResponse(
        products=[_build_response(p) for p in products],
        total=total, skip=skip, limit=limit,
    )


# ── 6. Single product (must be last) ─────────────────────────────────────────

@router.get("/{product_id}", response_model=schemas.ProductResponse)
def get_product(product_id: int, db: Session = Depends(get_db)):
    product = db.query(models.Product).filter(
        models.Product.id        == product_id,
        models.Product.is_active == True,
    ).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found.")
    return _build_response(product)
