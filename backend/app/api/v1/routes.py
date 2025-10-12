from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.app.core.config import Settings
from backend.app.core.models import ScanRequest, ScanResult
from backend.app.services.scanner import VulnerabilityScanner

router = APIRouter(prefix="/v1", tags=["vulnerability-scans"])


@router.post("/scan", response_model=ScanResult)
async def run_scan(payload: ScanRequest) -> ScanResult:
    settings = Settings()

    if not payload.repository_path:
        raise HTTPException(status_code=400, detail="repository_path is required")

    scanner = VulnerabilityScanner(settings=settings)
    try:
        result = await scanner.scan(payload)
    except FileNotFoundError as exc:  # noqa: BLE001
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return result
