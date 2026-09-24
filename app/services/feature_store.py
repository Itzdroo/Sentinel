from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

import networkx as nx

from app.models.schemas import AnomalyFinding, DecodedTransferEvent, WalletFeatureVector
from app.services.heuristics import ForensicsHeuristicsEngine


FEATURE_SCHEMA_VERSION = "sentinel.transfer.v1"


@dataclass(frozen=True)
class FeatureStoreResult:
    schema_version: str
    wallet_features: list[WalletFeatureVector]
    findings: list[AnomalyFinding]


class FeatureStore:
    """Shared, versioned interface for graph features and heuristic findings."""

    def __init__(self, heuristics: ForensicsHeuristicsEngine | None = None) -> None:
        self.heuristics = heuristics or ForensicsHeuristicsEngine()

    def analyze(
        self,
        graph: nx.DiGraph,
        events: list[DecodedTransferEvent],
        *,
        narrow_block_window: int = 2,
    ) -> FeatureStoreResult:
        findings = self.heuristics.analyze(
            graph,
            events,
            narrow_block_window=narrow_block_window,
        )
        features = self.extract_wallet_features(events, narrow_block_window=narrow_block_window)
        return FeatureStoreResult(
            schema_version=FEATURE_SCHEMA_VERSION,
            wallet_features=features,
            findings=findings,
        )

    @staticmethod
    def extract_wallet_features(
        events: list[DecodedTransferEvent],
        *,
        narrow_block_window: int = 2,
    ) -> list[WalletFeatureVector]:
        wallet_events: dict[tuple[str, str, str], list[DecodedTransferEvent]] = defaultdict(list)
        incoming: dict[tuple[str, str, str], float] = defaultdict(float)
        outgoing: dict[tuple[str, str, str], float] = defaultdict(float)
        counterparties: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        block_in: dict[tuple[str, str, str, int], float] = defaultdict(float)
        block_out: dict[tuple[str, str, str, int], float] = defaultdict(float)

        for event in events:
            sender = event.from_address.lower()
            recipient = event.to_address.lower()
            contract = event.contract_address.lower()
            token = event.token_symbol
            sender_key = (sender, contract, token)
            recipient_key = (recipient, contract, token)
            wallet_events[sender_key].append(event)
            if recipient != sender:
                wallet_events[recipient_key].append(event)
            outgoing[sender_key] += event.amount
            incoming[recipient_key] += event.amount
            counterparties[sender_key].add(recipient)
            counterparties[recipient_key].add(sender)
            block_out[(*sender_key, event.block_number)] += event.amount
            block_in[(*recipient_key, event.block_number)] += event.amount

        vectors: list[WalletFeatureVector] = []
        for address, contract, token in sorted(wallet_events):
            feature_key = (address, contract, token)
            wallet_activity = wallet_events[feature_key]
            total_in = incoming[feature_key]
            total_out = outgoing[feature_key]
            block_numbers = {
                block
                for wallet, contract_address, symbol, block in block_in.keys() | block_out.keys()
                if (wallet, contract_address, symbol) == feature_key
            }
            ratios = [
                min(block_in[(*feature_key, block)], block_out[(*feature_key, block)])
                / max(block_in[(*feature_key, block)], block_out[(*feature_key, block)])
                for block in block_numbers
                if max(block_in[(*feature_key, block)], block_out[(*feature_key, block)]) > 0
            ]
            vectors.append(
                WalletFeatureVector(
                    schema_version=FEATURE_SCHEMA_VERSION,
                    address=address,
                    contract_address=contract,
                    token_symbol=token,
                    event_count=len(wallet_activity),
                    total_in=round(total_in, 12),
                    total_out=round(total_out, 12),
                    unique_counterparty_count=len(counterparties[feature_key]),
                    out_in_ratio=round(total_out / total_in, 12) if total_in else 0.0,
                    max_outgoing_fanout=_max_outgoing_fanout(
                        address,
                        contract,
                        token,
                        wallet_activity,
                        narrow_block_window=narrow_block_window,
                    ),
                    max_same_block_in_out_ratio=round(max(ratios, default=0.0), 12),
                    first_block=min(event.block_number for event in wallet_activity),
                    last_block=max(event.block_number for event in wallet_activity),
                )
            )
        return vectors


def _max_outgoing_fanout(
    address: str,
    contract_address: str,
    token_symbol: str,
    events: list[DecodedTransferEvent],
    *,
    narrow_block_window: int,
) -> int:
    outgoing = sorted(
        (
            event
            for event in events
            if event.from_address.lower() == address
            and event.contract_address.lower() == contract_address
            and event.token_symbol == token_symbol
        ),
        key=lambda event: (event.block_number, event.log_index),
    ) if events else []
    maximum = 0
    for index, first in enumerate(outgoing):
        recipients = {
            event.to_address.lower()
            for event in outgoing[index:]
            if 0 <= event.block_number - first.block_number <= narrow_block_window
        }
        maximum = max(maximum, len(recipients))
    return maximum
