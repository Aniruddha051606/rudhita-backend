"""
main.py  —  FastAPI Application Entry Point (PATCHED)

Changes from audit:
  - /docs and /redoc are disabled in production (ENV=production)
  - /health/pool requires admin auth — no longer public
  - Structured JSON-style logging configured at startup
  - Request ID middleware added (X-Request-ID header on every response)
  - Generic 500 handler added — no stack traces leak to clients
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

# ── Logging — configure before anything else ──────────────────────────────────
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

# ── Detect environment ────────────────────────────────────────────────────────
IS_PRODUCTION = os.getenv("ENV", "development").lower() == "production"
logger.info("Starting Rudhita API — mode=%s", "production" if IS_PRODUCTION else "development")

# ── Auto-create tables (safe for now; migrate to Alembic before v2 schema change) ──
models.Base.metadata.create_all(bind=engine)

# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── App — docs disabled in production ────────────────────────────────────────
app = FastAPI(
    title       = "Rudhita E-Commerce API",
    description = "Backend for Rudhita — clothing, jewellery & lifestyle.",
    version     = "2.1.0",
    docs_url    = None if IS_PRODUCTION else "/docs",    # FIX: hidden in prod
    redoc_url   = None if IS_PRODUCTION else "/redoc",   # FIX: hidden in prod
    openapi_url = None if IS_PRODUCTION else "/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── FIX: Generic 500 handler — never leak stack traces to clients ─────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please try again later."},
    )

# ── FIX: Request ID middleware — every request gets a traceable ID ────────────
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id               = str(uuid.uuid4())[:8]
    request.state.request_id = request_id
    logger.info("→ %s %s [rid=%s]", request.method, request.url.path, request_id)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    logger.info("← %s %s %s [rid=%s]",
                request.method, request.url.path, response.status_code, request_id)
    return response

# ── CORS ──────────────────────────────────────────────────────────────────────
_raw_origins   = os.getenv("ALLOWED_ORIGINS", "")
allowed_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]
if not allowed_origins:
    if IS_PRODUCTION:
        logger.error("ALLOWED_ORIGINS is not set — CORS will block all requests in production!")
        allowed_origins = []   # block everything rather than allow everything
    else:
        allowed_origins = ["http://localhost:3000", "http://127.0.0.1:5500"]

app.add_middleware(
    CORSMiddleware,
    allow_origins     = allowed_origins,
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(products_router)
app.include_router(cart_router)
app.include_router(orders_router)
app.include_router(admin_router)
app.include_router(user_router)


# ── Health check (public) ─────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
def health_check(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"status": "online", "service": "Rudhita API v2.1", "db": "connected"}


# ── FIX: Pool stats now require admin auth ────────────────────────────────────
@app.get("/health/pool", tags=["Health"], include_in_schema=not IS_PRODUCTION)
def pool_stats(_: models.User = Depends(require_admin)):
    """Internal monitoring endpoint — admin only."""
    pool = engine.pool
    return {
        "pool_size":   pool.size(),
        "checked_in":  pool.checkedin(),
        "checked_out": pool.checkedout(),
        "overflow":    pool.overflow(),
    }
