# upload.py
# ─────────────────────────────────────────────────────────────────────────────
# Image upload via Cloudflare R2 using PRESIGNED URLs.
#
# Why presigned URLs (and not proxying the file through FastAPI):
#   • The R2 secret key NEVER reaches the browser — the frontend only ever
#     receives a short-lived, single-purpose PUT URL.
#   • The actual file bytes go browser → R2 directly, so they don't pass
#     through (and load) your backend/tunnel.
#
# Flow:
#   1. Admin frontend calls POST /admin/upload-url with { filename, content_type }.
#   2. Backend returns { upload_url, public_url }.
#   3. Frontend does a plain fetch(upload_url, { method: 'PUT', body: file }).
#   4. Frontend saves `public_url` as the product's image_url via the existing
#      product create/update endpoints.
#
# ── Required environment variables (.env) ───────────────────────────────────
#   R2_ACCOUNT_ID         = your Cloudflare account id
#   R2_ACCESS_KEY_ID      = R2 API token access key
#   R2_SECRET_ACCESS_KEY  = R2 API token secret
#   R2_BUCKET             = bucket name (e.g. rudhita-media)
#   R2_PUBLIC_BASE_URL    = public base, e.g. https://media.rudhita.com
#                           (an R2 custom domain or the r2.dev public URL)
#
# ── Dependency ───────────────────────────────────────────────────────────────
#   pip install boto3      (already added to requirements.txt)
# ─────────────────────────────────────────────────────────────────────────────
import os
import re
import uuid
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException

import schemas  # only used if you later add a typed response; kept import-light
import models
from admin import require_admin   # reuse the existing admin guard

logger = logging.getLogger("rudhita")
router = APIRouter(prefix="/admin", tags=["Upload"])

_ALLOWED_TYPES = {
    "image/jpeg": "jpg",
    "image/png":  "png",
    "image/webp": "webp",
    "image/avif": "avif",
    "image/gif":  "gif",
}
_MAX_PRESIGN_TTL = 300  # seconds the PUT URL stays valid


def _r2_client():
    """Build a boto3 S3 client pointed at the Cloudflare R2 endpoint."""
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Image upload is not configured on the server (boto3 missing).",
        )

    account_id = os.getenv("R2_ACCOUNT_ID")
    access_key = os.getenv("R2_ACCESS_KEY_ID")
    secret_key = os.getenv("R2_SECRET_ACCESS_KEY")
    if not all([account_id, access_key, secret_key]):
        raise HTTPException(
            status_code=503,
            detail="Image upload is not configured (missing R2 credentials).",
        )

    return boto3.client(
        "s3",
        endpoint_url=f"https://{account_id}.r2.cloudflarestorage.com",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4", region_name="auto"),
    )


def _safe_key(filename: str, ext: str) -> str:
    """Generate a collision-free, sanitized object key."""
    stem = re.sub(r"[^a-zA-Z0-9._-]", "-", (filename or "image").rsplit(".", 1)[0])[:40].strip("-") or "image"
    stamp = datetime.utcnow().strftime("%Y%m%d")
    return f"products/{stamp}/{stem}-{uuid.uuid4().hex[:10]}.{ext}"


@router.post("/upload-url")
def create_upload_url(
    payload: dict,
    current_user: models.User = Depends(require_admin),
):
    """
    Body: { "filename": "necklace.jpg", "content_type": "image/jpeg" }
    Returns: { "upload_url": "...", "public_url": "...", "key": "..." }
    """
    content_type = (payload or {}).get("content_type", "")
    filename     = (payload or {}).get("filename", "image")

    ext = _ALLOWED_TYPES.get(content_type)
    if not ext:
        raise HTTPException(
            status_code=400,
            detail="Unsupported image type. Use JPEG, PNG, WEBP, AVIF, or GIF.",
        )

    bucket      = os.getenv("R2_BUCKET")
    public_base = os.getenv("R2_PUBLIC_BASE_URL", "").rstrip("/")
    if not bucket or not public_base:
        raise HTTPException(status_code=503, detail="Image upload bucket is not configured.")

    key    = _safe_key(filename, ext)
    client = _r2_client()

    try:
        upload_url = client.generate_presigned_url(
            "put_object",
            Params={"Bucket": bucket, "Key": key, "ContentType": content_type},
            ExpiresIn=_MAX_PRESIGN_TTL,
        )
    except Exception as exc:
        logger.error("Failed to presign R2 upload: %s", exc)
        raise HTTPException(status_code=502, detail="Could not create upload URL.")

    return {
        "upload_url": upload_url,
        "public_url": f"{public_base}/{key}",
        "key":        key,
        "expires_in": _MAX_PRESIGN_TTL,
    }
