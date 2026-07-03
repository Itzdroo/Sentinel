from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field


APP_DIR = Path(__file__).resolve().parents[1]
STATIC_DIR = APP_DIR / "static"


class Settings(BaseModel):
    ethereum_rpc_url: str = Field(default="http://localhost:8545")
    rpc_timeout_seconds: int = Field(default=20, ge=1, le=120)
    block_chunk_size: int = Field(default=5_000, ge=1, le=100_000)
    max_total_logs: int = Field(default=2_000, ge=1, le=100_000)
    max_trace_addresses: int = Field(default=100, ge=1, le=10_000)
    etherscan_api_key: str | None = None
    etherscan_base_url: str = Field(default="https://api.etherscan.io/api")
    etherscan_calls_per_second: int = Field(default=5, ge=1, le=5)
    cache_enabled: bool = True
    cache_ttl_seconds: int = Field(default=900, ge=0)
    persistence_path: Path = Field(default=APP_DIR.parent / "data" / "analyzer_cache.sqlite3")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            ethereum_rpc_url=os.getenv("ETHEREUM_RPC_URL", "http://localhost:8545"),
            rpc_timeout_seconds=int(os.getenv("RPC_TIMEOUT_SECONDS", "20")),
            block_chunk_size=int(os.getenv("BLOCK_CHUNK_SIZE", "5000")),
            max_total_logs=int(os.getenv("MAX_TOTAL_LOGS", "2000")),
            max_trace_addresses=int(os.getenv("MAX_TRACE_ADDRESSES", "100")),
            etherscan_api_key=os.getenv("ETHERSCAN_API_KEY") or None,
            etherscan_base_url=os.getenv("ETHERSCAN_BASE_URL", "https://api.etherscan.io/api"),
            etherscan_calls_per_second=int(os.getenv("ETHERSCAN_CALLS_PER_SECOND", "5")),
            cache_enabled=os.getenv("CACHE_ENABLED", "true").lower() in {"1", "true", "yes", "on"},
            cache_ttl_seconds=int(os.getenv("CACHE_TTL_SECONDS", "900")),
            persistence_path=Path(os.getenv("PERSISTENCE_PATH", str(APP_DIR.parent / "data" / "analyzer_cache.sqlite3"))),
        )
