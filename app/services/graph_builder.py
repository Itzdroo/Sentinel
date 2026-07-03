from __future__ import annotations

import networkx as nx

from app.models.schemas import DecodedTransferEvent


class GraphConstructionFactory:
    def build(self, events: list[DecodedTransferEvent], *, max_depth: int = 4) -> nx.MultiDiGraph:
        capped_depth = min(max_depth, 4)
        graph = nx.MultiDiGraph()
        for event in events:
            if event.depth > capped_depth:
                continue
            self._ensure_node(graph, event.from_address)
            self._ensure_node(graph, event.to_address)
            graph.add_edge(
                event.from_address,
                event.to_address,
                weight=event.amount,
                token=event.token_symbol,
                asset_standard=event.asset_standard,
                event_type=event.event_type,
                token_id=event.token_id,
                timestamp=event.block_timestamp,
                tx_hash=event.tx_hash,
                tx_hashes=[event.tx_hash],
                transfer_count=1,
                transfers=[event.model_dump()],
            )
            graph.nodes[event.from_address]["total_out"] += event.amount
            graph.nodes[event.to_address]["total_in"] += event.amount
        return graph

    @staticmethod
    def _ensure_node(graph: nx.DiGraph, address: str) -> None:
        if address in graph:
            return
        graph.add_node(address, label=short_address(address), total_in=0.0, total_out=0.0)


def short_address(address: str) -> str:
    if len(address) <= 12:
        return address
    return f"{address[:6]}...{address[-4:]}"
