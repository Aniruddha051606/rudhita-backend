"""
auth.py  Ã¢â‚¬â€  Authentication Routes (PATCHED)

Changes from audit:
  - register_user(): no longer reveals whether email exists (prevents enumeration)
  - register_user(): calls send_otp_email() instead of print()
  - _generate_otp():  stores HMAC hash of OTP, not plain text
  - verify_otp():    uses verify_otp_hash() for constant-time comparison
  - login():         returns both access_token AND refresh_token
  - logout():        adds JTI to TokenBlocklist so token is truly invalid
  - NEW /auth/refresh: issues a new access_token from a valid refresh_token
"""

import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm

import models
import schemas
import utils
from database import get_db

router  = APIRouter(prefix="/auth", tags=["Authentication"])
limiter = Limiter(key_func=get_remote_address)


# Ã¢â€â‚¬Ã¢â€â‚¬ Internal helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬


from datetime import timedelta

def _generate_otp(db: Session, email: str) -> str:
    db.query(models.OTP).filter(models.OTP.email == email).delete()
    otp_plain  = str(secrets.randbelow(900_000) + 100_000)
    otp_hashed = utils.hash_otp(otp_plain)
    expiry     = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.add(models.OTP(email=email, otp_code=otp_hashed, expires_at=expiry))
    db.commit()
    return otp_plain


# Ã¢â€â‚¬Ã¢â€â‚¬ Register Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

@router.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("3/hour")
def register_user(
    request: Request,
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
):
    """
    FIX 1: Always returns the same response whether the email exists or not.
            This prevents attackers from probing which emails are registered.
    FIX 2: OTP is emailed via SMTP, never printed to stdout.
    """
    existing = db.query(models.User).filter(models.User.email == user.email).first()
    if not existing:
        new_user = models.User(
            name          = user.name,
            email         = user.email,
            password_hash = utils.hash_password(user.password),
            phone         = user.phone,
            is_verified   = False,
        )
        db.add(new_user)
        db.commit()

    # Generate and EMAIL the OTP (never print it)
    if not existing or not existing.is_verified:
        otp_plain = _generate_otp(db, user.email)
        utils.send_otp_email(user.email, otp_plain)

    # Same message regardless of outcome Ã¢â‚¬â€ prevents email enumeration
    return {
        "status":  "success",
        "message": "If this email is new, a verification code has been sent.",
    }


# Ã¢â€â‚¬Ã¢â€â‚¬ Verify OTP Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

# Maximum wrong OTP attempts before the code is invalidated
_MAX_OTP_ATTEMPTS = 5

@router.post("/verify-otp")
@limiter.limit("10/hour")
def verify_otp(
    request: Request,
    otp_data: schemas.OTPVerify,
    db: Session = Depends(get_db),
):
    """
    SECURITY FIX: Added per-email attempt counter.
    After 5 wrong guesses the OTP record is deleted, forcing the user to request
    a new code. This makes brute-forcing a 6-digit OTP computationally infeasible
    even when the per-IP rate limit is circumvented via proxies.
    """
    record = db.query(models.OTP).filter(
        models.OTP.email == otp_data.email
    ).first()

    if not record:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")

    # Check expiry
    expiry = record.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry < datetime.now(timezone.utc):
        db.delete(record)
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")

    # SECURITY FIX: Brute-force lockout — 5 wrong attempts invalidates the OTP
    if record.fail_count >= _MAX_OTP_ATTEMPTS:
        db.delete(record)
        db.commit()
        raise HTTPException(
            status_code=400,
            detail="Too many failed attempts. Please request a new verification code."
        )

    # Compare HMAC hashes (constant-time)
    if not utils.verify_otp_hash(otp_data.otp, record.otp_code):
        record.fail_count += 1
        remaining = _MAX_OTP_ATTEMPTS - record.fail_count
        db.commit()
        if remaining <= 0:
            db.delete(record)
            db.commit()
            raise HTTPException(
                status_code=400,
                detail="Too many failed attempts. Please request a new verification code."
            )
        raise HTTPException(
            status_code=400,
            detail=f"Invalid code. {remaining} attempt(s) remaining."
        )

    user = db.query(models.User).filter(models.User.email == otp_data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.is_verified = True
    db.delete(record)
    db.commit()
    return {"status": "success", "message": "Account successfully verified!"}


# Ã¢â€â‚¬Ã¢â€â‚¬ Resend OTP Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

@router.post("/resend-otp")
@limiter.limit("5/hour")
def resend_otp(
    request: Request,
    data: schemas.ResendOTP,
    db: Session = Depends(get_db),
):
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if user and not user.is_verified:
        otp_plain = _generate_otp(db, data.email)
        utils.send_otp_email(data.email, otp_plain)

    # Same message always Ã¢â‚¬â€ prevents enumeration
    return {
        "status":  "success",
        "message": "If this email is registered and unverified, a new code has been sent.",
    }


# Ã¢â€â‚¬Ã¢â€â‚¬ Login Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

@router.post("/login", response_model=schemas.Token)
@limiter.limit("5/minute")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """
    Returns both access_token (short-lived) and refresh_token (long-lived).
    The refresh_token is stored in the DB and can be revoked on logout.
    """
    invalid = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid credentials.",
    )
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not utils.verify_password(form_data.password, user.password_hash):
        raise invalid
    if not user.is_verified:
        raise invalid

    access_token              = utils.create_access_token({"sub": user.email, "id": user.id})
    refresh_token_str, expiry = utils.create_refresh_token()

    db.add(models.RefreshToken(
        user_id    = user.id,
        token      = refresh_token_str,
        expires_at = expiry,
    ))
    db.commit()

    return {
        "access_token":  access_token,
        "refresh_token": refresh_token_str,
        "token_type":    "bearer",
    }


# Ã¢â€â‚¬Ã¢â€â‚¬ Refresh access token Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

@router.post("/refresh", response_model=schemas.Token)
def refresh_access_token(
    payload: schemas.RefreshRequest,
    db: Session = Depends(get_db),
):
    """
    Validates a long-lived refresh token and issues a new short-lived access token.
    Call this when you receive a 401 on any protected endpoint.
    """
    record = db.query(models.RefreshToken).filter(
        models.RefreshToken.token == payload.refresh_token
    ).first()

    if not record:
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    expiry = record.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry < datetime.now(timezone.utc):
        db.delete(record)
        db.commit()
        raise HTTPException(status_code=401, detail="Refresh token has expired. Please log in again.")

    user = db.query(models.User).filter(models.User.id == record.user_id).first()
    if not user or not user.is_verified:
        raise HTTPException(status_code=401, detail="User not found or unverified.")

    new_access   = utils.create_access_token({"sub": user.email, "id": user.id})
    new_refresh, new_expiry = utils.create_refresh_token()

    # Rotate: delete old token, issue new one (prevents refresh token reuse)
    db.delete(record)
    db.add(models.RefreshToken(user_id=user.id, token=new_refresh, expires_at=new_expiry))
    db.commit()

    return {
        "access_token":  new_access,
        "refresh_token": new_refresh,
        "token_type":    "bearer",
    }


# Ã¢â€â‚¬Ã¢â€â‚¬ Me Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

@router.get("/me", response_model=schemas.UserResponse)
def get_me(current_user: models.User = Depends(utils.get_current_user)):
    return current_user


# Ã¢â€â‚¬Ã¢â€â‚¬ Logout Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

@router.post("/logout")
def logout(
    token_str: str = Depends(utils.oauth2_scheme),
    # BUG 28 FIX: Optional prevents FastAPI rejecting requests with no body
    payload: Optional[schemas.RefreshRequest] = None,
    db: Session = Depends(get_db),
):
    """
    FIX: Adds the access token's JTI to the blocklist so it's truly invalid.
         Also deletes the matching refresh token if supplied.

    Frontend should send the refresh_token in the request body
    so both tokens are revoked in one call.
    """
    import jwt as pyjwt
    from jwt.exceptions import InvalidTokenError

    try:
        decoded = pyjwt.decode(
            token_str, utils.SECRET_KEY,
            algorithms=[utils.ALGORITHM],
            options={"verify_exp": False},   # we want to blocklist even near-expired tokens
        )
        jti        = decoded.get("jti")
        exp_ts     = decoded.get("exp")
        expires_at = (
            datetime.fromtimestamp(exp_ts, tz=timezone.utc)
            if exp_ts else datetime.now(timezone.utc)
        )
        if jti:
            db.merge(models.TokenBlocklist(jti=jti, expires_at=expires_at))
    except InvalidTokenError:
        pass  # already invalid Ã¢â‚¬â€ that's fine

    # Revoke refresh token if provided
    if payload and payload.refresh_token:
        db.query(models.RefreshToken).filter(
            models.RefreshToken.token == payload.refresh_token
        ).delete()

    db.commit()
    return {"status": "success", "message": "Logged out successfully."}