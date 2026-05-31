"""
main.py  Ã¢â‚¬â€  FastAPI Application Entry Point (PATCHED)

Changes from audit:
  - /docs and /redoc are disabled in production (ENV=production)
  - /health/pool requires admin auth Ã¢â‚¬â€ no longer public
  - Structured JSON-style logging configured at startup
  - Request ID middleware added (X-Request-ID header on every response)
  - Generic 500 handler added Ã¢â‚¬â€ no stack traces leak to clients
  - CORS patched to explicitly allow rudhita.com and vercel frontend
"""

import os
import uuid
import logging
import logging.config

from fastapi              import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses    import JSONResponse
from slowapi               import Limiter, _rate_limit_exceeded_handler
from slowapi.util          import get_remote_address
from slowapi.errors        import RateLimitExceeded
from sqlalchemy.orm        import Session
from sqlalchemy            import text

from database import engine, get_db
import models
from auth     import router as auth_router
from products import router as products_router
from cart     import router as cart_router
from orders   import router as orders_router
from admin    import router as admin_router, require_admin
from user     import router as user_router
from webhook  import router as webhook_router
from reviews  import router as reviews_router
from wishlist import router as wishlist_router
from upload   import router as upload_router

# Ã¢â‚¬â€Ã¢â‚¬â€ Logging Ã¢â‚¬â€ configure before anything else Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€
logging.config.dictConfig({
    "version":    1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%S",
        }
    },
    "handlers": {
        "console": {
            "class":     "logging.StreamHandler",
            "formatter": "default",
            "stream":    "ext://sys.stdout",
        }
    },
    "root": {"level": "INFO", "handlers": ["console"]},
    "loggers": {
        "rudhita":   {"level": "INFO",  "propagate": True},
        "sqlalchemy.engine": {"level": "WARNING", "propagate": True},  # set INFO to debug queries
        "uvicorn":   {"level": "INFO",  "propagate": False, "handlers": ["console"]},
    },
}) 
logger = logging.getLogger("rudhita")

# Ã¢â‚¬â€Ã¢â‚¬â€ Detect environment Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€
IS_PRODUCTION = os.getenv("ENV", "development").lower() == "production"
logger.info("Starting Rudhita API Ã¢â‚¬â€ mode=%s", "production" if IS_PRODUCTION else "development")

# Ã¢â‚¬â€Ã¢â‚¬â€ Auto-create tables (safe for now; migrate to Alembic before v2 schema change) Ã¢â‚¬â€Ã¢â‚¬â€
models.Base.metadata.create_all(bind=engine)

# Ã¢â‚¬â€Ã¢â‚¬â€ Rate limiter Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€
limiter = Limiter(key_func=get_remote_address)

# Ã¢â‚¬â€Ã¢â‚¬â€ App Ã¢â‚¬â€ docs disabled in production Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€
app = FastAPI(
    title       = "Rudhita E-Commerce API",
    description = "Backend for Rudhita Ã¢â‚¬â€ clothing, jewellery & lifestyle.",
    version     = "2.1.0",
    docs_url    = None if IS_PRODUCTION else "/docs",    # FIX: hidden in prod
    redoc_url   = None if IS_PRODUCTION else "/redoc",   # FIX: hidden in prod
    openapi_url = None if IS_PRODUCTION else "/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Ã¢â‚¬â€Ã¢â‚¬â€ FIX: Generic 500 handler Ã¢â‚¬â€ never leak stack traces to clients Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please try again later."},
    )

# Ã¢â‚¬â€Ã¢â‚¬â€ FIX: Request ID middleware Ã¢â‚¬â€ every request gets a traceable ID Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id               = str(uuid.uuid4())[:8]
    request.state.request_id = request_id
    logger.info("Ã¢â€ â€™ %s %s [rid=%s]", request.method, request.url.path, request_id)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    logger.info("Ã¢â€ Â %s %s %s [rid=%s]",
                request.method, request.url.path, response.status_code, request_id)
    return response

# Ã¢â‚¬â€Ã¢â‚¬â€ CORS (UPDATED FOR PRODUCTION DOMAINS) Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€
_raw_origins   = os.getenv("ALLOWED_ORIGINS", "")
allowed_origins = [o.strip().rstrip("/") for o in _raw_origins.split(",") if o.strip()]

# Hard fallback to ensure live domains are always permitted
if not allowed_origins:
    allowed_origins = [
        "http://localhost:5173",              # Local Vite development
        "https://rudhita.vercel.app",         # Vercel fallback URL
        "https://rudhita-ten.vercel.app",     # Vercel production deployment
        "https://rudhita.com",                # Official Live Domain
        "https://www.rudhita.com",            # Official Live Domain (www)
    ]
    if IS_PRODUCTION:
        logger.warning("ALLOWED_ORIGINS missing from .env! Using secure default list.")

app.add_middleware(
    CORSMiddleware,
    allow_origins     = allowed_origins,
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# Ã¢â‚¬â€Ã¢â‚¬â€ Routers Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€
app.include_router(auth_router)
app.include_router(products_router)
app.include_router(cart_router)
app.include_router(orders_router)
app.include_router(admin_router)
app.include_router(user_router)
app.include_router(webhook_router)   # Razorpay payment event safety net
app.include_router(reviews_router)
app.include_router(wishlist_router)
app.include_router(upload_router)


# Ã¢â‚¬â€Ã¢â‚¬â€ Health check (public) Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€
@app.get("/", tags=["Health"])
def health_check(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"status": "online", "service": "Rudhita API v2.1", "db": "connected"}


# Ã¢â‚¬â€Ã¢â‚¬â€ FIX: Pool stats now require admin auth Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€Ã¢â‚¬â€
@app.get("/health/pool", tags=["Health"], include_in_schema=not IS_PRODUCTION)
def pool_stats(_: models.User = Depends(require_admin)):
    """Internal monitoring endpoint Ã¢â‚¬â€ admin only."""
    pool = engine.pool
    return {
        "pool_size":   pool.size(),
        "checked_in":  pool.checkedin(),
        "checked_out": pool.checkedout(),
        "overflow":    pool.overflow(),
    }
