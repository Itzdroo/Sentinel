from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

import networkx as nx

from app.models.schemas import (
    AnalysisProfile,
    AnomalyFinding,
    DecodedTransferEvent,
    ProtocolRoleFinding,
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
        highlights = [
            f"{len(defi_roles)} protocol role candidates detected across {len(token_counter)} token symbols.",
            f"{graph.number_of_edges()} directed transfer links compiled for router/pool flow review.",
        ]
        if exchange_roles:
            highlights.append(f"{len(exchange_roles)} exchange candidate wallets flagged for verification.")
        if anomalies:
            highlights.append(f"{len(anomalies)} anomaly findings overlap the transfer graph.")
        return UseCaseReport(
            profile="defi_audit",
            title="DeFi Protocol Auditing",
            summary="Trace fund flows through complex swap routers and liquidity pools for security reviews.",
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
                "Inspect anomaly paths that pass through protocol candidates.",
            ],
            protocol_roles=defi_roles + exchange_roles,
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
        blocks = [event.block_number for event in events]
        unique_recipients = {event.to_address for event in events}
        high_findings = [finding for finding in anomalies if finding.severity == "high"]
        highlights = [
            f"{len(unique_recipients)} unique recipient addresses observed.",
            f"{len(high_findings)} high-severity findings identified for escalation.",
        ]
        if blocks:
            highlights.append(f"Transfer activity spans blocks {min(blocks)} through {max(blocks)}.")
        if exchange_roles:
            highlights.append(f"{len(exchange_roles)} exchange candidate wallets detected in the response path.")
        return UseCaseReport(
            profile="incident_response",
            title="Incident Response",
            summary="Rapidly map attacker fund dispersal post-exploit, enabling faster response and recovery.",
            key_metrics={
                "recipient_count": len(unique_recipients),
                "high_severity_findings": len(high_findings),
                "dispersal_candidate_count": len(dispersal_roles),
                "first_block": min(blocks) if blocks else None,
                "last_block": max(blocks) if blocks else None,
            },
            highlights=highlights,
            recommended_actions=[
                "Prioritize high-severity peeling and fan-out paths for exchange or bridge notifications.",
                "Escalate any exchange candidate wallet that receives or sends the suspicious chain.",
                "Export the report payload before widening the block range.",
                "Increase max depth only after confirming the root address and initial dispersal path.",
            ],
            protocol_roles=dispersal_roles + exchange_roles,
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
        highlights = [
            f"{len(events)} decoded ERC-20 transfer events retained in the evidence set.",
            f"{len(tx_hashes)} unique transactions represented in the visual report.",
            f"{len(anomalies)} heuristic findings included for audit review.",
        ]
        if exchange_roles:
            highlights.append(f"{len(exchange_roles)} exchange candidate wallets were flagged in the evidence set.")
        return UseCaseReport(
            profile="compliance_reporting",
            title="Compliance Reporting",
            summary="Generate transparent, visual transaction reports for regulatory and internal audit workflows.",
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
                "Preserve transaction hashes and graph payload as reproducible evidence references.",
            ],
            protocol_roles=roles + exchange_roles,
        )
