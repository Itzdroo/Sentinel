from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from app.models.schemas import AnalyzeRequest, SankeyPayload


SCHEMA_VERSION = "tool-b-cache-v1"


class AnalysisCache:
    def __init__(self, db_path: Path, *, ttl_seconds: int) -> None:
        self.db_path = db_path
        self.ttl_seconds = ttl_seconds
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def get(self, request: AnalyzeRequest, *, provider_fingerprint: str) -> SankeyPayload | None:
        cache_key = self.cache_key(request, provider_fingerprint=provider_fingerprint)
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                "select created_at, payload_json from analysis_cache where cache_key = ?",
                (cache_key,),
            ).fetchone()
        if row is None:
            return None
        created_at, payload_json = row
        if self.ttl_seconds and int(time.time()) - int(created_at) > self.ttl_seconds:
            self.delete(cache_key)
            return None
        payload = SankeyPayload.model_validate_json(payload_json)
        return payload.model_copy(
            update={
                "metadata": payload.metadata.model_copy(update={"cache_status": "hit"}),
            }
        )

    def set(self, request: AnalyzeRequest, payload: SankeyPayload, *, provider_fingerprint: str) -> None:
        cache_key = self.cache_key(request, provider_fingerprint=provider_fingerprint)
        payload_json = payload.model_dump_json()
        request_json = json.dumps(self._request_fingerprint(request), sort_keys=True, separators=(",", ":"))
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                insert into analysis_cache(cache_key, created_at, request_json, payload_json)
                values (?, ?, ?, ?)
                on conflict(cache_key) do update set
                    created_at = excluded.created_at,
                    request_json = excluded.request_json,
                    payload_json = excluded.payload_json
                """,
                (cache_key, int(time.time()), request_json, payload_json),
            )
            connection.commit()

    def delete(self, cache_key: str) -> None:
        with sqlite3.connect(self.db_path) as connection:
            connection.execute("delete from analysis_cache where cache_key = ?", (cache_key,))
            connection.commit()

    def cache_key(self, request: AnalyzeRequest, *, provider_fingerprint: str) -> str:
        payload: dict[str, Any] = {
            "schema": SCHEMA_VERSION,
            "provider": provider_fingerprint,
            "request": self._request_fingerprint(request),
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _initialize(self) -> None:
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                create table if not exists analysis_cache (
                    cache_key text primary key,
                    created_at integer not null,
                    request_json text not null,
                    payload_json text not null
                )
                """
            )
            connection.execute("create index if not exists idx_analysis_cache_created_at on analysis_cache(created_at)")
            connection.commit()

    @staticmethod
    def _request_fingerprint(request: AnalyzeRequest) -> dict[str, Any]:
        data = request.model_dump(mode="json")
        data.pop("use_cache", None)
        return data


def provider_fingerprint(provider_url: str) -> str:
    return hashlib.sha256(provider_url.encode("utf-8")).hexdigest()[:16]
