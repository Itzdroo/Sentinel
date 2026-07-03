from __future__ import annotations

from collections import defaultdict

import networkx as nx

from app.models.schemas import AnomalyFinding, DecodedTransferEvent


class ForensicsHeuristicsEngine:
    def analyze(
        self,
        graph: nx.DiGraph,
        events: list[DecodedTransferEvent],
        *,
        narrow_block_window: int = 2,
    ) -> list[AnomalyFinding]:
        findings = []
        findings.extend(self.detect_peeling_chains(events, narrow_block_window=narrow_block_window))
        findings.extend(self.detect_splitter_mixers(events, narrow_block_window=narrow_block_window))
        return findings

    def detect_peeling_chains(
        self,
        events: list[DecodedTransferEvent],
        *,
        narrow_block_window: int = 2,
    ) -> list[AnomalyFinding]:
        ordered = sorted(events, key=lambda event: (event.block_number, event.log_index))
        last_incoming: dict[tuple[str, str], DecodedTransferEvent] = {}
        seen_addresses: set[str] = set()
        candidate_by_sender: dict[str, DecodedTransferEvent] = {}

        for event in ordered:
            sender_key = (event.from_address.lower(), event.token_symbol)
            incoming = last_incoming.get(sender_key)
            recipient_was_new = event.to_address.lower() not in seen_addresses
            if incoming and recipient_was_new:
                block_delta = event.block_number - incoming.block_number
                amount_ratio = event.amount / incoming.amount if incoming.amount else 0
                if 0 <= block_delta <= narrow_block_window and amount_ratio >= 0.9:
                    candidate_by_sender[event.from_address.lower()] = event

            seen_addresses.add(event.from_address.lower())
            seen_addresses.add(event.to_address.lower())
            last_incoming[(event.to_address.lower(), event.token_symbol)] = event

        findings: list[AnomalyFinding] = []
        visited_roots: set[str] = set()
        for sender_key, first_event in candidate_by_sender.items():
            if sender_key in visited_roots:
                continue
            path = [first_event.from_address, first_event.to_address]
            tx_hashes = [first_event.tx_hash]
            current = first_event.to_address.lower()
            visited_chain = {sender_key}

            while current in candidate_by_sender and current not in visited_chain:
                visited_chain.add(current)
                next_event = candidate_by_sender[current]
                path.append(next_event.to_address)
                tx_hashes.append(next_event.tx_hash)
                current = next_event.to_address.lower()

            visited_roots.update(visited_chain)
            if len(path) >= 3:
                findings.append(
                    AnomalyFinding(
                        type="peeling_chain",
                        severity="high" if len(path) >= 4 else "medium",
                        description="Sequential >90% forward transfers to new addresses detected",
                        node=path[0],
                        path=path,
                        tx_hashes=tx_hashes,
                        evidence={
                            "hop_count": len(path) - 1,
                            "narrow_block_window": narrow_block_window,
                        },
                    )
                )
        return findings

    def detect_splitter_mixers(
        self,
        events: list[DecodedTransferEvent],
        *,
        narrow_block_window: int = 2,
    ) -> list[AnomalyFinding]:
        outgoing: dict[str, list[DecodedTransferEvent]] = defaultdict(list)
        for event in events:
            outgoing[event.from_address.lower()].append(event)

        findings: list[AnomalyFinding] = []
        for sender_key, sender_events in outgoing.items():
            sorted_events = sorted(sender_events, key=lambda event: (event.block_number, event.log_index))
            for start_index, start_event in enumerate(sorted_events):
                window = [
                    event
                    for event in sorted_events[start_index:]
                    if 0 <= event.block_number - start_event.block_number <= narrow_block_window
                ]
                recipients = {event.to_address.lower() for event in window}
                if len(recipients) > 5:
                    tx_hashes = sorted({event.tx_hash for event in window})
                    findings.append(
                        AnomalyFinding(
                            type="splitter_mixer",
                            severity="high" if len(recipients) >= 10 else "medium",
                            description="Fan-out to more than five distinct recipients in a narrow block window",
                            node=start_event.from_address,
                            path=[start_event.from_address] + sorted({event.to_address for event in window}),
                            tx_hashes=tx_hashes,
                            evidence={
                                "recipient_count": len(recipients),
                                "start_block": start_event.block_number,
                                "end_block": max(event.block_number for event in window),
                                "narrow_block_window": narrow_block_window,
                            },
                        )
                    )
                    break
        return findings
