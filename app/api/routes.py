from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from app.core.exceptions import AnalyzerError
from app.models.schemas import AnalysisProfile, AnalyzeRequest, SankeyPayload
from app.services.pipeline import FlowAnalyzer


router = APIRouter(prefix="/api", tags=["analysis"])


def get_analyzer(request: Request) -> FlowAnalyzer:
    return request.app.state.analyzer


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/analyze", response_model=SankeyPayload)
async def analyze_get(
    target: str = Query(..., min_length=42, max_length=66),
    from_block: int = Query(..., ge=0),
    to_block: str = Query("latest"),
    max_depth: int = Query(1, ge=0, le=4),
    narrow_block_window: int = Query(2, ge=0, le=100),
    analysis_profile: AnalysisProfile = Query("incident_response"),
    use_cache: bool = Query(True),
    incident_started_at: datetime | None = Query(None),
    complaint_received_at: datetime | None = Query(None),
    analyzer: FlowAnalyzer = Depends(get_analyzer),
) -> SankeyPayload:
    request = AnalyzeRequest(
        target=target,
        from_block=from_block,
        to_block=to_block,
        max_depth=max_depth,
        narrow_block_window=narrow_block_window,
        analysis_profile=analysis_profile,
        use_cache=use_cache,
        incident_started_at=incident_started_at,
        complaint_received_at=complaint_received_at,
    )
    return await _run_analysis(analyzer, request)


@router.post("/analyze", response_model=SankeyPayload)
async def analyze_post(
    request: AnalyzeRequest,
    analyzer: FlowAnalyzer = Depends(get_analyzer),
) -> SankeyPayload:
    return await _run_analysis(analyzer, request)


async def _run_analysis(analyzer: FlowAnalyzer, request: AnalyzeRequest) -> SankeyPayload:
    try:
        return await run_in_threadpool(analyzer.analyze, request)
    except AnalyzerError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"message": exc.message, "details": exc.details}) from exc
