from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.core.config import STATIC_DIR, Settings
from app.services.pipeline import FlowAnalyzer


def create_app() -> FastAPI:
    settings = Settings.from_env()
    app = FastAPI(title="Smart Contract Flow Analyzer", version="0.1.0")
    app.state.settings = settings
    app.state.analyzer = FlowAnalyzer(settings)
    app.include_router(router)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    return app


app = create_app()
