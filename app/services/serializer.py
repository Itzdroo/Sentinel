from __future__ import annotations

import networkx as nx

from app.models.schemas import AnomalyFinding, AnalysisMetadata, GraphLink, GraphNode, SankeyPayload, UseCaseReport


class D3PayloadSerializer:
    def serialize(
        self,
        graph: nx.DiGraph,
        *,
        anomalies: list[AnomalyFinding],
        report: UseCaseReport,
        metadata: AnalysisMetadata,
    ) -> SankeyPayload:
        visible_graph = build_clue_graph(graph, anomalies=anomalies, report=report)
        node_ids = list(visible_graph.nodes)
        index_by_id = {node_id: index for index, node_id in enumerate(node_ids)}
        nodes = [
            GraphNode(
                id=node_id,
                label=str(visible_graph.nodes[node_id].get("label", node_id)),
                total_in=float(visible_graph.nodes[node_id].get("total_in", 0.0)),
                total_out=float(visible_graph.nodes[node_id].get("total_out", 0.0)),
                role=visible_graph.nodes[node_id].get("role"),
                tags=list(visible_graph.nodes[node_id].get("tags", [])),
                risk_score=float(visible_graph.nodes[node_id].get("risk_score", 0.0)),
            )
            for node_id in node_ids
        ]

        links: list[GraphLink] = []
        for source, target, data in visible_graph.edges(data=True):
            links.append(
                GraphLink(
                    source=index_by_id[source],
                    target=index_by_id[target],
                    value=float(data.get("weight", 0.0)),
                    tx_hash=str(data.get("tx_hash", "")),
                    tx_hashes=list(data.get("tx_hashes", [])),
                    token=str(data.get("token", "")),
                    asset_standard=str(data.get("asset_standard", "")),
                    event_type=str(data.get("event_type", "")),
                    token_id=data.get("token_id"),
                    timestamp=data.get("timestamp"),
                    transfer_count=int(data.get("transfer_count", 1)),
                )
            )
        visible_metadata = metadata.model_copy(
            update={
                "graph_node_count": visible_graph.number_of_nodes(),
                "graph_link_count": visible_graph.number_of_edges(),
                "visible_graph_node_count": visible_graph.number_of_nodes(),
                "visible_graph_link_count": visible_graph.number_of_edges(),
            }
        )
        return SankeyPayload(nodes=nodes, links=links, anomalies=anomalies, report=report, metadata=visible_metadata)


def build_clue_graph(
    graph: nx.DiGraph,
    *,
    anomalies: list[AnomalyFinding],
    report: UseCaseReport,
    max_context_hops: int = 0,
    max_visible_nodes: int = 24,
) -> nx.MultiDiGraph:
    suspicious_nodes = collect_suspicious_nodes(graph, anomalies, report)
    if not suspicious_nodes:
        suspicious_nodes = top_nodes_by_risk(graph, limit=12)

    ranked_suspicious_nodes = rank_nodes(graph, suspicious_nodes, limit=max_visible_nodes)
    visible_nodes = set(ranked_suspicious_nodes)
    frontier = set(suspicious_nodes)
    for _ in range(max_context_hops):
        next_frontier: set[str] = set()
        for node in frontier:
            if node not in graph:
                continue
            next_frontier.update(graph.predecessors(node))
            next_frontier.update(graph.successors(node))
        next_frontier.difference_update(visible_nodes)
        visible_nodes.update(next_frontier)
        frontier = next_frontier

    if not visible_nodes:
        visible_nodes = set(graph.nodes)

    visible_graph = graph.subgraph(visible_nodes).copy()
    for node in visible_graph.nodes:
        node_data = visible_graph.nodes[node]
        node_data["tags"] = list(node_data.get("tags", []))
        if node in suspicious_nodes:
            node_data["tags"] = sorted(set(node_data["tags"] + ["suspicious"]))
    return visible_graph


def collect_suspicious_nodes(graph: nx.DiGraph, anomalies: list[AnomalyFinding], report: UseCaseReport) -> set[str]:
    suspicious_nodes: set[str] = set()
    for node, data in graph.nodes(data=True):
        risk_score = float(data.get("risk_score", 0.0))
        tags = set(data.get("tags", []))
        if risk_score >= 0.5 or tags.intersection({"anomaly_path", "dispersal_hub", "collector_wallet", "liquidity_pool_candidate", "swap_router_candidate"}):
            suspicious_nodes.add(node)
    for finding in anomalies:
        if finding.node:
            suspicious_nodes.add(finding.node)
        suspicious_nodes.update(finding.path)
    for role in report.protocol_roles:
        suspicious_nodes.add(role.address)
    return suspicious_nodes


def rank_nodes(graph: nx.DiGraph, node_ids: set[str], *, limit: int) -> list[str]:
    return sorted(
        node_ids,
        key=lambda node: (
            float(graph.nodes[node].get("risk_score", 0.0)),
            float(graph.nodes[node].get("total_in", 0.0)) + float(graph.nodes[node].get("total_out", 0.0)),
            graph.in_degree(node) + graph.out_degree(node),
        ),
        reverse=True,
    )[:limit]


def top_nodes_by_risk(graph: nx.DiGraph, *, limit: int) -> list[str]:
    ranked = sorted(
        graph.nodes,
        key=lambda node: (
            float(graph.nodes[node].get("risk_score", 0.0)),
            float(graph.nodes[node].get("total_in", 0.0)) + float(graph.nodes[node].get("total_out", 0.0)),
            graph.in_degree(node) + graph.out_degree(node),
        ),
        reverse=True,
    )
    return ranked[:limit]
