from __future__ import annotations

import logging
import time
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.core.config import STATIC_DIR, Settings
from app.core.logging_config import configure_structured_logging, request_id_context
from app.services.pipeline import FlowAnalyzer


logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    configure_structured_logging()
    settings = Settings.from_env()
    app = FastAPI(title="Smart Contract Flow Analyzer", version="0.1.0")
    app.state.settings = settings
    app.state.analyzer = FlowAnalyzer(settings)
    app.include_router(router)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.middleware("http")
    async def log_request(request: Request, call_next):
        request_id = uuid4().hex
        context_token = request_id_context.set(request_id)
        started_at = time.perf_counter()
        status_code = 500
        request_failed = False
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-ID"] = request_id
            return response
        except Exception as exc:
            request_failed = True
            logger.error(
                "http_request_failed",
                extra={
                    "event_name": "http_request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": status_code,
                    "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
                    "error_type": type(exc).__name__,
                },
            )
            raise
        finally:
            if not request_failed:
                logger.info(
                    "http_request_completed",
                    extra={
                        "event_name": "http_request",
                        "request_id": request_id,
                        "method": request.method,
                        "path": request.url.path,
                        "status_code": status_code,
                        "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
                    },
                )
            request_id_context.reset(context_token)

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    return app


app = create_app()
