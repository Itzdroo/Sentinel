from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from app.models.schemas import AnalyzeRequest
from app.services.web3_client import EthereumClient


@dataclass
class IngestionResult:
    raw_logs: list[dict[str, Any]]
    warnings: list[str] = field(default_factory=list)


class IngestionEngine:
    def __init__(self, client: EthereumClient) -> None:
        self.client = client

    def fetch(self, request: AnalyzeRequest) -> IngestionResult:
        from_block, to_block = self.client.resolve_block_range(request.from_block, request.to_block)
        if request.target_type == "transaction":
            logs = self.client.get_transfer_logs_for_transaction(request.target)
            for log in logs:
                log["analysisDepth"] = 0
            return IngestionResult(raw_logs=logs)
        return self._trace_address(
            root_address=request.target,
            from_block=from_block,
            to_block=to_block,
            max_depth=min(request.max_depth, 4),
        )

    def _trace_address(self, *, root_address: str, from_block: int, to_block: int, max_depth: int) -> IngestionResult:
        root = self.client.checksum_address(root_address)
        queue: deque[tuple[str, int]] = deque([(root, 0)])
        seen_addresses: set[str] = set()
        queued_addresses: set[str] = {root.lower()}
        seen_logs: dict[tuple[str, int], dict[str, Any]] = {}
        warnings: list[str] = []

        contract_logs = self.client.get_transfer_logs_for_contract(root, from_block, to_block)
        for log in contract_logs:
            log["analysisDepth"] = 0
            remember_log(seen_logs, self.client.log_tx_hash(log), int(log["logIndex"]), log)

        while queue:
            address, depth = queue.popleft()
            address_key = address.lower()
            if address_key in seen_addresses:
                continue
            if len(seen_addresses) >= self.client.settings.max_trace_addresses:
                warnings.append("trace address cap reached; results are truncated")
                break
            seen_addresses.add(address_key)

            participant_logs = self.client.get_transfer_logs_for_participant(address, from_block, to_block)
            for log in participant_logs:
                log["analysisDepth"] = depth
                key = (self.client.log_tx_hash(log), int(log["logIndex"]))
                remember_log(seen_logs, key[0], key[1], log)
                if depth < max_depth:
                    for neighbor in extract_transfer_neighbors(log):
                        neighbor_key = neighbor.lower()
                        if neighbor_key not in seen_addresses and neighbor_key not in queued_addresses:
                            queue.append((neighbor, depth + 1))
                            queued_addresses.add(neighbor_key)

            if len(seen_logs) >= self.client.settings.max_total_logs:
                warnings.append("log cap reached; results are truncated")
                break

        logs = sorted(seen_logs.values(), key=lambda item: (int(item["blockNumber"]), int(item["logIndex"])))
        return IngestionResult(raw_logs=logs[: self.client.settings.max_total_logs], warnings=warnings)


def remember_log(seen_logs: dict[tuple[str, int], dict[str, Any]], tx_hash: str, log_index: int, log: dict[str, Any]) -> None:
    key = (tx_hash, log_index)
    existing = seen_logs.get(key)
    if existing is None or int(log.get("analysisDepth", 0)) < int(existing.get("analysisDepth", 0)):
        seen_logs[key] = log


def extract_transfer_neighbors(log: dict[str, Any]) -> list[str]:
    topics = log.get("topics", [])
    if len(topics) < 3:
        return []
    neighbors = []
    for topic in (topics[1], topics[2]):
        normalized = str(topic).removeprefix("0x")
        if len(normalized) == 64:
            neighbors.append("0x" + normalized[-40:])
    return neighbors
