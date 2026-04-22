"""
auth.py  â€”  Authentication Routes (PATCHED)

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


# â”€â”€ Internal helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


from datetime import timedelta

def _generate_otp(db: Session, email: str) -> str:
    db.query(models.OTP).filter(models.OTP.email == email).delete()
    otp_plain  = str(secrets.randbelow(900_000) + 100_000)
    otp_hashed = utils.hash_otp(otp_plain)
    expiry     = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.add(models.OTP(email=email, otp_code=otp_hashed, expires_at=expiry))
    db.commit()
    return otp_plain


# â”€â”€ Register â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    # Same message regardless of outcome â€” prevents email enumeration
    return {
        "status":  "success",
        "message": "If this email is new, a verification code has been sent.",
    }


# â”€â”€ Verify OTP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post("/verify-otp")
@limiter.limit("10/hour")
def verify_otp(
    request: Request,
    otp_data: schemas.OTPVerify,
    db: Session = Depends(get_db),
):
    record = db.query(models.OTP).filter(
        models.OTP.email == otp_data.email
    ).first()

    if not record:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")

    # FIX: check expiry first, then constant-time hash comparison
    expiry = record.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry < datetime.now(timezone.utc):
        db.delete(record)
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")

    # FIX: compare hashes, not plain text
    if not utils.verify_otp_hash(otp_data.otp, record.otp_code):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")

    user = db.query(models.User).filter(models.User.email == otp_data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.is_verified = True
    db.delete(record)
    db.commit()
    return {"status": "success", "message": "Account successfully verified!"}


# â”€â”€ Resend OTP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    # Same message always â€” prevents enumeration
    return {
        "status":  "success",
        "message": "If this email is registered and unverified, a new code has been sent.",
    }


# â”€â”€ Login â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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


# â”€â”€ Refresh access token â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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


# â”€â”€ Me â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get("/me", response_model=schemas.UserResponse)
def get_me(current_user: models.User = Depends(utils.get_current_user)):
    return current_user


# â”€â”€ Logout â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        pass  # already invalid â€” that's fine

    # Revoke refresh token if provided
    if payload and payload.refresh_token:
        db.query(models.RefreshToken).filter(
            models.RefreshToken.token == payload.refresh_token
        ).delete()

    db.commit()
    return {"status": "success", "message": "Logged out successfully."}
