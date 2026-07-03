from __future__ import annotations


class AnalyzerError(Exception):
    status_code = 500

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(AnalyzerError):
    status_code = 500


class RpcConnectionError(AnalyzerError):
    status_code = 503


class RpcQueryError(AnalyzerError):
    status_code = 502


class DecodeError(AnalyzerError):
    status_code = 422


class RateLimitError(AnalyzerError):
    status_code = 429
