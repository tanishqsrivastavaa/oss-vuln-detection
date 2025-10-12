from __future__ import annotations

from fastapi import FastAPI

from backend.app.api.v1.routes import router as api_router
from backend.app.core.config import Settings

settings = Settings()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.include_router(api_router)


@app.get("/health", tags=["health"])
async def healthcheck() -> dict[str, str]:
    return {"status": "ok"}
