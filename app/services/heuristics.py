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
        findings.extend(self.detect_flash_loans(events))
        findings.extend(self.detect_liquidity_drains(events, narrow_block_window=narrow_block_window))
        findings.extend(self.detect_rug_pulls(graph, events, narrow_block_window=narrow_block_window))
        findings.extend(self.detect_bridge_activity(events))
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

    def detect_flash_loans(self, events: list[DecodedTransferEvent]) -> list[AnomalyFinding]:
        grouped: dict[tuple[str, int], list[DecodedTransferEvent]] = defaultdict(list)
        for event in events:
            grouped[(event.from_address.lower(), event.block_number)].append(event)

        findings: list[AnomalyFinding] = []
        for (address, block_number), batch in grouped.items():
            total_in = sum(event.amount for event in events if event.to_address.lower() == address and event.block_number == block_number)
            total_out = sum(event.amount for event in batch)
            counterparties = {event.to_address.lower() for event in batch}
            if len(batch) >= 2 and total_in > 0 and total_out > 0:
                ratio = min(total_in, total_out) / max(total_in, total_out)
                if ratio >= 0.8 and len(counterparties) >= 2 and total_out >= total_in * 0.8:
                    findings.append(
                        AnomalyFinding(
                            type="flash_loan",
                            severity="high" if len(batch) >= 4 else "medium",
                            description="Large same-block in/out movement resembles a flash-loan style loop",
                            node=address,
                            path=[event.tx_hash for event in batch],
                            tx_hashes=[event.tx_hash for event in batch],
                            evidence={
                                "block_number": block_number,
                                "batch_size": len(batch),
                                "counterparty_count": len(counterparties),
                                "in_out_ratio": round(ratio, 4),
                            },
                        )
                    )
        return findings

    def detect_liquidity_drains(
        self,
        events: list[DecodedTransferEvent],
        *,
        narrow_block_window: int = 2,
    ) -> list[AnomalyFinding]:
        incoming_by_node: dict[tuple[str, str], list[DecodedTransferEvent]] = defaultdict(list)
        outgoing_by_node: dict[tuple[str, str], list[DecodedTransferEvent]] = defaultdict(list)
        for event in events:
            incoming_by_node[(event.to_address.lower(), event.token_symbol)].append(event)
            outgoing_by_node[(event.from_address.lower(), event.token_symbol)].append(event)

        findings: list[AnomalyFinding] = []
        for (node, token), incoming_events in incoming_by_node.items():
            outgoing_events = outgoing_by_node.get((node, token), [])
            total_in = sum(event.amount for event in incoming_events)
            total_out = sum(event.amount for event in outgoing_events)
            if total_in <= 0 or total_out <= 0:
                continue
            last_in_block = max(event.block_number for event in incoming_events)
            first_out_block = min(event.block_number for event in outgoing_events)
            if first_out_block - last_in_block <= narrow_block_window and total_out >= total_in * 0.8:
                findings.append(
                    AnomalyFinding(
                        type="liquidity_drain",
                        severity="high" if total_out >= total_in * 0.95 else "medium",
                        description="Incoming value is rapidly drained from the same wallet within a narrow window",
                        node=node,
                        path=[event.tx_hash for event in incoming_events + outgoing_events],
                        tx_hashes=sorted({event.tx_hash for event in incoming_events + outgoing_events}),
                        evidence={
                            "token": token,
                            "total_in": round(total_in, 8),
                            "total_out": round(total_out, 8),
                            "last_in_block": last_in_block,
                            "first_out_block": first_out_block,
                        },
                    )
                )
        return findings

    def detect_rug_pulls(
        self,
        graph: nx.DiGraph,
        events: list[DecodedTransferEvent],
        *,
        narrow_block_window: int = 2,
    ) -> list[AnomalyFinding]:
        findings: list[AnomalyFinding] = []
        for node in graph.nodes:
            role = graph.nodes[node].get("role")
            tags = set(graph.nodes[node].get("tags", []))
            if role not in {"liquidity_pool_candidate", "swap_router_candidate"} and "liquidity_pool_candidate" not in tags:
                continue
            incoming = [event for event in events if event.to_address.lower() == node.lower()]
            outgoing = [event for event in events if event.from_address.lower() == node.lower()]
            if not incoming or not outgoing:
                continue
            total_in = sum(event.amount for event in incoming)
            total_out = sum(event.amount for event in outgoing)
            if total_in <= 0:
                continue
            drain_ratio = total_out / total_in
            unique_recipients = {event.to_address.lower() for event in outgoing}
            if drain_ratio >= 0.9 and len(unique_recipients) >= 3:
                findings.append(
                    AnomalyFinding(
                        type="rug_pull",
                        severity="high",
                        description="Liquidity-style wallet shows sudden broad outflow consistent with a rug-pull pattern",
                        node=node,
                        path=[event.tx_hash for event in incoming[:3] + outgoing[:3]],
                        tx_hashes=sorted({event.tx_hash for event in incoming + outgoing}),
                        evidence={
                            "drain_ratio": round(drain_ratio, 4),
                            "total_in": round(total_in, 8),
                            "total_out": round(total_out, 8),
                            "unique_recipients": len(unique_recipients),
                            "window": narrow_block_window,
                        },
                    )
                )
        return findings

    def detect_bridge_activity(self, events: list[DecodedTransferEvent]) -> list[AnomalyFinding]:
        bridge_like_nodes: dict[str, list[DecodedTransferEvent]] = defaultdict(list)
        for event in events:
            if event.asset_standard == "ERC721":
                continue
            if event.amount <= 0:
                continue
            bridge_like_nodes[event.to_address.lower()].append(event)
            bridge_like_nodes[event.from_address.lower()].append(event)

        findings: list[AnomalyFinding] = []
        for node, node_events in bridge_like_nodes.items():
            counterparties = {event.from_address.lower() for event in node_events} | {event.to_address.lower() for event in node_events}
            if len(node_events) >= 6 and len(counterparties) >= 5:
                findings.append(
                    AnomalyFinding(
                        type="bridge_activity",
                        severity="medium",
                        description="High-volume wallet movement suggests a bridge or cross-chain handoff point",
                        node=node,
                        path=[event.tx_hash for event in node_events[:6]],
                        tx_hashes=sorted({event.tx_hash for event in node_events}),
                        evidence={
                            "event_count": len(node_events),
                            "counterparty_count": len(counterparties),
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
