from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

import models
import schemas
from database import get_db
from utils import get_current_user, hash_password, verify_password

router = APIRouter(prefix="/user", tags=["User Profile"])


# â”€â”€ PROFILE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get("/profile", response_model=schemas.UserResponse)
def get_profile(current_user: models.User = Depends(get_current_user)):
    return current_user


@router.put("/profile", response_model=schemas.UserResponse)
def update_profile(
    update: schemas.UserProfileUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if update.name is not None:
        current_user.name = update.name
    if update.phone is not None:
        current_user.phone = update.phone
    if update.password is not None:
        # BUG 9 FIX: enforce min 8 to match schema
        # BUG 31 FIX: verify current password before allowing change
        if not update.current_password:
            raise HTTPException(status_code=400, detail="Current password is required to set a new password.")
        if not verify_password(update.current_password, current_user.password_hash):
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        if len(update.password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
        current_user.password_hash = hash_password(update.password)
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    return current_user


# â”€â”€ ADDRESSES â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get("/addresses")
def list_addresses(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Returns {addresses: [...]} â€” frontend reads addressesData.addresses"""
    addrs = (
        db.query(models.Address)
        .filter(models.Address.user_id == current_user.id)
        .order_by(models.Address.is_default.desc(), models.Address.created_at.desc())
        .all()
    )
    return {"addresses": [_serialize_address(a) for a in addrs]}


@router.post("/addresses", status_code=201)
def add_address(
    data: schemas.AddressCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if data.is_default:
        _clear_default(db, current_user.id)
    address = models.Address(
        user_id=current_user.id,
        name=data.name,
        phone=data.phone,
        street=data.street,
        city=data.city,
        state=data.state,
        pincode=data.pincode,
        is_default=data.is_default,
    )
    db.add(address)
    db.commit()
    db.refresh(address)
    return _serialize_address(address)


@router.put("/addresses/{address_id}")
def update_address(
    address_id: int,
    data: schemas.AddressUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    address = _get_own_address(db, address_id, current_user.id)
    if data.is_default:
        _clear_default(db, current_user.id)
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(address, field, value)
    db.commit()
    db.refresh(address)
    return _serialize_address(address)


@router.delete("/addresses/{address_id}")
def delete_address(
    address_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    address = _get_own_address(db, address_id, current_user.id)
    db.delete(address)
    db.commit()
    return {"status": "success", "message": "Address deleted."}


@router.patch("/addresses/{address_id}/set-default")
def set_default_address(
    address_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    _clear_default(db, current_user.id)
    address = _get_own_address(db, address_id, current_user.id)
    address.is_default = True
    db.commit()
    db.refresh(address)
    return _serialize_address(address)


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _serialize_address(a: models.Address) -> dict:
    """Return camelCase `isDefault` so frontend's a.isDefault works."""
    return {
        "id": a.id,
        "name": a.name,
        "phone": a.phone,
        "street": a.street,
        "city": a.city,
        "state": a.state,
        "pincode": a.pincode,
        "isDefault": a.is_default,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


def _get_own_address(db: Session, address_id: int, user_id: int) -> models.Address:
    address = db.query(models.Address).filter(
        models.Address.id == address_id,
        models.Address.user_id == user_id,
    ).first()
    if not address:
        raise HTTPException(status_code=404, detail="Address not found.")
    return address


def _clear_default(db: Session, user_id: int):
    db.query(models.Address).filter(
        models.Address.user_id == user_id,
        models.Address.is_default == True,
    ).update({"is_default": False})
