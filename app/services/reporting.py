from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

import networkx as nx

from app.models.schemas import (
    AnalysisProfile,
    AnomalyFinding,
    DecodedTransferEvent,
    ProtocolRoleFinding,
    RankedDispersalCandidate,
    UseCaseReport,
)


class UseCaseReportBuilder:
    def build(
        self,
        graph: nx.DiGraph,
        events: list[DecodedTransferEvent],
        anomalies: list[AnomalyFinding],
        *,
        profile: AnalysisProfile,
    ) -> UseCaseReport:
        protocol_roles = self.detect_protocol_roles(graph, events)
        self.annotate_graph(graph, protocol_roles, anomalies)

        if profile == "defi_audit":
            return self._defi_audit_report(graph, events, anomalies, protocol_roles)
        if profile == "compliance_reporting":
            return self._compliance_report(graph, events, anomalies, protocol_roles)
        return self._incident_response_report(graph, events, anomalies, protocol_roles)

    def detect_protocol_roles(self, graph: nx.DiGraph, events: list[DecodedTransferEvent]) -> list[ProtocolRoleFinding]:
        tokens_by_node: dict[str, set[str]] = defaultdict(set)
        blocks_by_node: dict[str, set[int]] = defaultdict(set)
        txs_by_node: dict[str, set[str]] = defaultdict(set)

        for event in events:
            for address in (event.from_address, event.to_address):
                tokens_by_node[address].add(event.token_symbol)
                blocks_by_node[address].add(event.block_number)
                txs_by_node[address].add(event.tx_hash)

        roles: list[ProtocolRoleFinding] = []
        for node in graph.nodes:
            in_degree = graph.in_degree(node)
            out_degree = graph.out_degree(node)
            total_in = float(graph.nodes[node].get("total_in", 0.0))
            total_out = float(graph.nodes[node].get("total_out", 0.0))
            token_count = len(tokens_by_node.get(node, set()))
            tx_count = len(txs_by_node.get(node, set()))
            balance_ratio = min(total_in, total_out) / max(total_in, total_out) if max(total_in, total_out) else 0.0
            unique_counterparties = len(set(graph.predecessors(node))) + len(set(graph.successors(node)))

            if in_degree >= 2 and out_degree >= 2 and token_count >= 2 and balance_ratio >= 0.2:
                roles.append(
                    ProtocolRoleFinding(
                        address=node,
                        role="liquidity_pool_candidate",
                        confidence=min(0.95, 0.45 + (token_count * 0.08) + (balance_ratio * 0.25)),
                        evidence={
                            "in_degree": in_degree,
                            "out_degree": out_degree,
                            "token_count": token_count,
                            "balance_ratio": round(balance_ratio, 4),
                            "tx_count": tx_count,
                        },
                    )
                )
            if in_degree >= 4 and out_degree >= 4 and unique_counterparties >= 8 and balance_ratio >= 0.4:
                roles.append(
                    ProtocolRoleFinding(
                        address=node,
                        role="exchange_candidate",
                        confidence=min(0.96, 0.5 + (unique_counterparties * 0.03) + (balance_ratio * 0.2)),
                        evidence={
                            "in_degree": in_degree,
                            "out_degree": out_degree,
                            "unique_counterparties": unique_counterparties,
                            "balance_ratio": round(balance_ratio, 4),
                            "tx_count": tx_count,
                        },
                    )
                )
            if in_degree >= 4 and out_degree >= 4 and unique_counterparties >= 6 and balance_ratio >= 0.5:
                roles.append(
                    ProtocolRoleFinding(
                        address=node,
                        role="bridge_candidate",
                        confidence=min(0.93, 0.48 + (unique_counterparties * 0.03) + (balance_ratio * 0.18)),
                        evidence={
                            "in_degree": in_degree,
                            "out_degree": out_degree,
                            "unique_counterparties": unique_counterparties,
                            "balance_ratio": round(balance_ratio, 4),
                            "tx_count": tx_count,
                        },
                    )
                )
            elif out_degree >= 4 and token_count >= 2:
                roles.append(
                    ProtocolRoleFinding(
                        address=node,
                        role="swap_router_candidate",
                        confidence=min(0.9, 0.4 + (out_degree * 0.05) + (token_count * 0.08)),
                        evidence={
                            "out_degree": out_degree,
                            "token_count": token_count,
                            "block_count": len(blocks_by_node.get(node, set())),
                            "tx_count": tx_count,
                        },
                    )
                )

            if out_degree > 5:
                roles.append(
                    ProtocolRoleFinding(
                        address=node,
                        role="dispersal_hub",
                        confidence=min(0.95, 0.5 + (out_degree * 0.04)),
                        evidence={"out_degree": out_degree, "total_out": total_out, "tx_count": tx_count},
                    )
                )
            if in_degree > 5 and total_out < total_in * 0.25:
                roles.append(
                    ProtocolRoleFinding(
                        address=node,
                        role="collector_wallet",
                        confidence=min(0.92, 0.45 + (in_degree * 0.04)),
                        evidence={"in_degree": in_degree, "total_in": total_in, "total_out": total_out},
                    )
                )
        return sorted(roles, key=lambda item: item.confidence, reverse=True)[:20]

    def annotate_graph(
        self,
        graph: nx.DiGraph,
        roles: list[ProtocolRoleFinding],
        anomalies: list[AnomalyFinding],
    ) -> None:
        role_by_address = {role.address: role for role in roles}
        anomaly_nodes = {finding.node for finding in anomalies if finding.node}
        anomaly_path_nodes = {address for finding in anomalies for address in finding.path}
        for node in graph.nodes:
            tags: list[str] = []
            risk_score = 0.0
            role = role_by_address.get(node)
            if role:
                tags.append(role.role)
                risk_score = max(risk_score, role.confidence)
            if node in anomaly_nodes or node in anomaly_path_nodes:
                tags.append("anomaly_path")
                risk_score = max(risk_score, 0.85)
            graph.nodes[node]["role"] = role.role if role else None
            graph.nodes[node]["tags"] = sorted(set(tags))
            graph.nodes[node]["risk_score"] = round(min(1.0, risk_score), 4)

    def _defi_audit_report(
        self,
        graph: nx.DiGraph,
        events: list[DecodedTransferEvent],
        anomalies: list[AnomalyFinding],
        roles: list[ProtocolRoleFinding],
    ) -> UseCaseReport:
        defi_roles = [role for role in roles if role.role in {"swap_router_candidate", "liquidity_pool_candidate"}]
        exchange_roles = [role for role in roles if role.role == "exchange_candidate"]
        token_counter = Counter(event.token_symbol for event in events)
        narrative = self._reconstruction_narrative(graph, events, anomalies, "contract behavior around router and pool activity")
        highlights = [
            f"{len(defi_roles)} protocol role candidates detected across {len(token_counter)} token symbols.",
            f"{graph.number_of_edges()} directed transfer links compiled for router/pool flow review.",
            narrative,
        ]
        if exchange_roles:
            highlights.append(f"{len(exchange_roles)} exchange candidate wallets flagged for verification.")
        bridge_roles = [role for role in roles if role.role == "bridge_candidate"]
        if bridge_roles:
            highlights.append(f"{len(bridge_roles)} bridge candidate touchpoints detected for cross-chain review.")
        if anomalies:
            highlights.append(f"{len(anomalies)} anomaly findings overlap the transfer graph.")
        return UseCaseReport(
            profile="defi_audit",
            title="DeFi Protocol Auditing",
            summary="Trace fund flows through complex swap routers and liquidity pools to explain contract behavior, not just wallet movement.",
            key_metrics={
                "protocol_candidate_count": len(defi_roles),
                "token_symbol_count": len(token_counter),
                "transfer_count": len(events),
                "graph_density": round(nx.density(graph), 6) if graph.number_of_nodes() > 1 else 0.0,
            },
            highlights=highlights,
            recommended_actions=[
                "Review high-confidence liquidity pool candidates for abnormal reserve movement.",
                "Compare router candidates against known protocol deployments before audit sign-off.",
                "Check exchange candidate wallets for custodial entry or exit points.",
                "Escalate bridge candidate wallets for cross-chain validation.",
                "Inspect anomaly paths that pass through protocol candidates.",
            ],
            protocol_roles=defi_roles + exchange_roles + bridge_roles,
        )

    def _incident_response_report(
        self,
        graph: nx.DiGraph,
        events: list[DecodedTransferEvent],
        anomalies: list[AnomalyFinding],
        roles: list[ProtocolRoleFinding],
    ) -> UseCaseReport:
        dispersal_roles = [role for role in roles if role.role in {"dispersal_hub", "collector_wallet"}]
        exchange_roles = [role for role in roles if role.role == "exchange_candidate"]
        bridge_roles = [role for role in roles if role.role == "bridge_candidate"]
        ranked_candidates = self._rank_dispersal_candidates(graph, events, roles, anomalies)
        candidate_count = len(ranked_candidates) if ranked_candidates else len(dispersal_roles)
        blocks = [event.block_number for event in events]
        unique_recipients = {event.to_address for event in events}
        high_findings = [finding for finding in anomalies if finding.severity == "high"]
        narrative = self._reconstruction_narrative(graph, events, anomalies, "exploit dispersal from the suspicious root wallet")
        highlights = [
            f"{len(unique_recipients)} unique recipient addresses observed.",
            f"{len(high_findings)} high-severity findings identified for escalation.",
            narrative,
        ]
        if blocks:
            highlights.append(f"Transfer activity spans blocks {min(blocks)} through {max(blocks)}.")
        if exchange_roles:
            highlights.append(f"{len(exchange_roles)} exchange candidate wallets detected in the response path.")
        if bridge_roles:
            highlights.append(f"{len(bridge_roles)} bridge candidate wallets detected in the response path.")
        return UseCaseReport(
            profile="incident_response",
            title="Incident Response",
            summary="Rapidly reconstruct exploit dispersal post-incident so investigators can map the fraudulent wallet, follow the money, and act faster.",
            key_metrics={
                "recipient_count": len(unique_recipients),
                "high_severity_findings": len(high_findings),
                "dispersal_candidate_count": candidate_count,
                "first_block": min(blocks) if blocks else None,
                "last_block": max(blocks) if blocks else None,
            },
            highlights=highlights,
            recommended_actions=[
                "Prioritize high-severity peeling and fan-out paths for exchange or bridge notifications.",
                "Escalate any exchange candidate wallet that receives or sends the suspicious chain.",
                "Inspect bridge candidate wallets for cross-chain exit points.",
                "Export the report payload before widening the block range.",
                "Increase max depth only after confirming the root address and initial dispersal path.",
            ],
            protocol_roles=dispersal_roles + exchange_roles + bridge_roles,
            ranked_dispersal_candidates=ranked_candidates,
            report_version="1.1.0",
        )

    def _compliance_report(
        self,
        graph: nx.DiGraph,
        events: list[DecodedTransferEvent],
        anomalies: list[AnomalyFinding],
        roles: list[ProtocolRoleFinding],
    ) -> UseCaseReport:
        total_value = sum(event.amount for event in events)
        token_counter = Counter(event.token_symbol for event in events)
        tx_hashes = {event.tx_hash for event in events}
        exchange_roles = [role for role in roles if role.role == "exchange_candidate"]
        bridge_roles = [role for role in roles if role.role == "bridge_candidate"]
        narrative = self._reconstruction_narrative(graph, events, anomalies, "evidence trail for compliance review")
        highlights = [
            f"{len(events)} decoded ERC-20 transfer events retained in the evidence set.",
            f"{len(tx_hashes)} unique transactions represented in the visual report.",
            f"{len(anomalies)} heuristic findings included for audit review.",
            narrative,
        ]
        if exchange_roles:
            highlights.append(f"{len(exchange_roles)} exchange candidate wallets were flagged in the evidence set.")
        if bridge_roles:
            highlights.append(f"{len(bridge_roles)} bridge candidate wallets were flagged in the evidence set.")
        return UseCaseReport(
            profile="compliance_reporting",
            title="Compliance Reporting",
            summary="Generate transparent, visual evidence reports that reconstruct what happened and preserve the transaction trail for review.",
            key_metrics={
                "decoded_transfer_count": len(events),
                "unique_transaction_count": len(tx_hashes),
                "unique_token_count": len(token_counter),
                "aggregate_display_value": round(total_value, 8),
                "graph_node_count": graph.number_of_nodes(),
                "graph_link_count": graph.number_of_edges(),
            },
            highlights=highlights,
            recommended_actions=[
                "Attach the exported JSON report to the case file with the RPC provider and block range.",
                "Review warnings before relying on the report for regulatory submission.",
                "Flag exchange candidate wallets as compliance touchpoints in the case notes.",
                "Flag bridge candidate wallets as cross-chain compliance touchpoints.",
                "Preserve transaction hashes and graph payload as reproducible evidence references.",
            ],
            protocol_roles=roles,
        )

    def _reconstruction_narrative(
        self,
        graph: nx.DiGraph,
        events: list[DecodedTransferEvent],
        anomalies: list[AnomalyFinding],
        focus: str,
    ) -> str:
        if not events:
            return f"No transfer trail was retained for {focus}."

        first_block = min(event.block_number for event in events)
        last_block = max(event.block_number for event in events)
        suspicious_nodes = {finding.node for finding in anomalies if finding.node}
        if suspicious_nodes:
            primary = sorted(suspicious_nodes)[0]
            return (
                f"Reconstructed {focus} from block {first_block} to {last_block}, "
                f"anchoring the trail around {primary} and the surrounding anomaly path."
            )
        root = max(
            graph.nodes,
            key=lambda node: float(graph.nodes[node].get("risk_score", 0.0)) if node in graph else 0.0,
            default=None,
        )
        if root:
            return f"Reconstructed {focus} from block {first_block} to {last_block} around {root}."
        return f"Reconstructed {focus} from block {first_block} to {last_block}."

    def _rank_dispersal_candidates(
        self,
        graph: nx.DiGraph,
        events: list[DecodedTransferEvent],
        roles: list[ProtocolRoleFinding],
        anomalies: list[AnomalyFinding],
    ) -> list[RankedDispersalCandidate]:
        if not events or not graph.nodes:
            return []

        exchange_addresses = {r.address.lower() for r in roles if r.role in {"exchange_candidate", "bridge_candidate"}}
        wallet_nodes = [n for n, data in graph.nodes(data=True) if data.get("kind") != "transaction"]

        if not wallet_nodes:
            return []

        root_address = events[0].from_address.lower()
        if root_address not in [w.lower() for w in wallet_nodes]:
            root_address = wallet_nodes[0].lower()

        undirected_g = graph.to_undirected()
        hop_distances: dict[str, int] = {}
        root_node_in_graph = events[0].from_address if events[0].from_address in undirected_g else wallet_nodes[0]

        for w in wallet_nodes:
            w_lower = w.lower()
            try:
                if root_node_in_graph in undirected_g and w in undirected_g:
                    dist = nx.shortest_path_length(undirected_g, source=root_node_in_graph, target=w)
                    hop_distances[w_lower] = max(1, int(dist))
                else:
                    hop_distances[w_lower] = 2
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                hop_distances[w_lower] = 3

        wallet_values: dict[str, float] = {}
        for w in wallet_nodes:
            data = graph.nodes[w]
            val = float(data.get("total_in", 0.0)) + float(data.get("total_out", 0.0))
            wallet_values[w.lower()] = val

        max_val = max(wallet_values.values()) if wallet_values and max(wallet_values.values()) > 0 else 1.0

        candidate_pool: set[str] = set()
        for r in roles:
            candidate_pool.add(r.address)
        for a in anomalies:
            if a.node:
                candidate_pool.add(a.node)
            for p in a.path:
                candidate_pool.add(p)

        if len(candidate_pool) < 5:
            sorted_by_val = sorted(wallet_nodes, key=lambda w: wallet_values.get(w.lower(), 0.0), reverse=True)
            for w in sorted_by_val:
                if w.lower() != root_address:
                    candidate_pool.add(w)

        candidate_pool = {w for w in candidate_pool if w.lower() != root_address and w in graph.nodes}

        scored_candidates = []
        for w in candidate_pool:
            w_lower = w.lower()
            val = wallet_values.get(w_lower, 0.0)
            val_score = min(1.0, val / max_val) if max_val > 0 else 0.0
            hops = hop_distances.get(w_lower, 2)
            hop_score = max(0.1, 1.0 - 0.25 * (hops - 1))
            is_ex = w_lower in exchange_addresses

            ex_bonus = 0.35 if is_ex else 0.0
            composite_score = round(min(0.99, (val_score * 0.4) + (hop_score * 0.35) + ex_bonus), 2)

            formatted_val = f"${val:,.2f}" if val > 100 else (f"{val:,.4f} tokens" if val > 0 else "direct transfer recipient")
            ex_str = "; flagged as Exchange/Bridge Touchpoint" if is_ex else ""
            justification_detail = f"{formatted_val} routed in {hops} hop{'s' if hops > 1 else ''}{ex_str}"

            scored_candidates.append({
                "address": w,
                "score": composite_score,
                "total_value": val,
                "hops": hops,
                "is_exchange": is_ex,
                "justification_detail": justification_detail,
            })

        scored_candidates.sort(key=lambda x: (x["score"], x["total_value"], -x["hops"]), reverse=True)

        results: list[RankedDispersalCandidate] = []
        for idx, c in enumerate(scored_candidates[:15], start=1):
            rank_justification = f"Rank {idx} — {c['justification_detail']}"
            results.append(
                RankedDispersalCandidate(
                    address=c["address"],
                    rank=idx,
                    score=c["score"],
                    total_value=c["total_value"],
                    hops=c["hops"],
                    is_exchange=c["is_exchange"],
                    justification=rank_justification,
                )
            )

        return results

