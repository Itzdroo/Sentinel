from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from app.core.exceptions import RateLimitError, RpcQueryError
from app.services.backoff import CallsPerSecondLimiter, is_retryable_message


class EtherscanClient:
    def __init__(self, *, api_key: str | None, base_url: str, calls_per_second: int = 5) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.limiter = CallsPerSecondLimiter(min(calls_per_second, 5))
        self._abi_cache: dict[str, list[dict[str, Any]] | None] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def get_contract_abi(self, address: str) -> list[dict[str, Any]] | None:
        cache_key = address.lower()
        if cache_key in self._abi_cache:
            return self._abi_cache[cache_key]
        if not self.enabled:
            self._abi_cache[cache_key] = None
            return None

        result = self._request(
            {
                "module": "contract",
                "action": "getabi",
                "address": address,
                "apikey": self.api_key or "",
            }
        )
        if not result:
            self._abi_cache[cache_key] = None
            return None
        try:
            abi = json.loads(result)
        except json.JSONDecodeError as exc:
            raise RpcQueryError("Etherscan returned malformed ABI JSON", details={"address": address}) from exc
        if not isinstance(abi, list):
            self._abi_cache[cache_key] = None
            return None
        self._abi_cache[cache_key] = abi
        return abi

    def _request(self, params: dict[str, str]) -> str | None:
        query = urllib.parse.urlencode(params)
        url = f"{self.base_url}?{query}"
        last_error: Exception | None = None
        for attempt in range(5):
            self.limiter.wait()
            try:
                with urllib.request.urlopen(url, timeout=20) as response:
                    payload = response.read().decode("utf-8")
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code == 429:
                    self._sleep(attempt)
                    continue
                if 500 <= exc.code < 600:
                    self._sleep(attempt)
                    continue
                raise RpcQueryError("Etherscan HTTP request failed", details={"status": exc.code}) from exc
            except urllib.error.URLError as exc:
                last_error = exc
                if is_retryable_message(str(exc)):
                    self._sleep(attempt)
                    continue
                raise RpcQueryError("Etherscan request failed", details={"error": str(exc)}) from exc

            try:
                data = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise RpcQueryError("Etherscan returned malformed JSON") from exc

            status = str(data.get("status", ""))
            message = str(data.get("message", ""))
            result = data.get("result")
            combined = f"{message} {result}"
            if status == "1":
                return str(result)
            if "no records" in combined.lower() or "not verified" in combined.lower():
                return None
            if is_retryable_message(combined):
                self._sleep(attempt)
                continue
            raise RpcQueryError("Etherscan API request failed", details={"message": message, "result": result})

        if last_error:
            raise RateLimitError("Etherscan rate limit persisted after retries") from last_error
        raise RateLimitError("Etherscan rate limit persisted after retries")

    @staticmethod
    def _sleep(attempt: int) -> None:
        time.sleep(min(8.0, 0.5 * (2**attempt)))
