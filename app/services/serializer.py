from __future__ import annotations

from collections.abc import Iterable

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
        visible_graph = build_cctv_graph(graph, anomalies=anomalies, report=report)
        node_ids = list(visible_graph.nodes)
        index_by_id = {node_id: index for index, node_id in enumerate(node_ids)}
        nodes = [
            GraphNode(
                id=node_id,
                label=str(visible_graph.nodes[node_id].get("label", node_id)),
                kind=str(visible_graph.nodes[node_id].get("kind", "wallet")),
                subtitle=visible_graph.nodes[node_id].get("subtitle"),
                detail=visible_graph.nodes[node_id].get("detail"),
                total_in=float(visible_graph.nodes[node_id].get("total_in", 0.0)),
                total_out=float(visible_graph.nodes[node_id].get("total_out", 0.0)),
                role=visible_graph.nodes[node_id].get("role"),
                tags=list(visible_graph.nodes[node_id].get("tags", [])),
                risk_score=float(visible_graph.nodes[node_id].get("risk_score", 0.0)),
                tx_hashes=list(visible_graph.nodes[node_id].get("tx_hashes", [])),
                report_hint=visible_graph.nodes[node_id].get("report_hint"),
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
                    kind=str(data.get("kind", "wallet_to_transaction")),
                    asset_standard=str(data.get("asset_standard", "")),
                    event_type=str(data.get("event_type", "")),
                    token_id=data.get("token_id"),
                    timestamp=data.get("timestamp"),
                    transfer_count=int(data.get("transfer_count", 1)),
                )
            )

        visible_metadata = metadata.model_copy(
            update={
                "full_graph_node_count": graph.number_of_nodes(),
                "full_graph_link_count": graph.number_of_edges(),
                "graph_node_count": visible_graph.number_of_nodes(),
                "graph_link_count": visible_graph.number_of_edges(),
                "visible_graph_node_count": visible_graph.number_of_nodes(),
                "visible_graph_link_count": visible_graph.number_of_edges(),
            }
        )
        return SankeyPayload(nodes=nodes, links=links, anomalies=anomalies, report=report, metadata=visible_metadata)


def build_cctv_graph(
    graph: nx.DiGraph,
    *,
    anomalies: list[AnomalyFinding],
    report: UseCaseReport,
    max_visible_wallets: int = 16,
) -> nx.MultiDiGraph:
    suspicious_wallets = collect_suspicious_wallets(graph, anomalies, report)
    if not suspicious_wallets:
        suspicious_wallets = top_wallets_by_risk(graph, limit=max_visible_wallets)
    suspicious_wallets = set(top_wallets_by_risk(graph, limit=max_visible_wallets, allowed=suspicious_wallets))

    visible_events = []
    for source, target, data in graph.edges(data=True):
        if source in suspicious_wallets or target in suspicious_wallets or "anomaly_path" in graph.nodes[source].get("tags", []) or "anomaly_path" in graph.nodes[target].get("tags", []):
            visible_events.extend(data.get("transfers", []))

    if not visible_events:
        visible_events = collect_fallback_transfers(graph, suspicious_wallets)

    visible_graph = nx.MultiDiGraph()
    wallet_nodes_added: set[str] = set()
    for transfer in visible_events:
        source_wallet = transfer["from_address"]
        target_wallet = transfer["to_address"]
        tx_node_id = transaction_node_id(transfer["tx_hash"], transfer.get("log_index", 0))

        add_wallet_node(visible_graph, graph, source_wallet, suspicious_wallets)
        add_wallet_node(visible_graph, graph, target_wallet, suspicious_wallets)
        add_tx_node(visible_graph, transfer, tx_node_id, source_wallet, target_wallet)

        visible_graph.add_edge(
            source_wallet,
            tx_node_id,
            weight=float(transfer["amount"]),
            kind="wallet_to_transaction",
            token=transfer["token_symbol"],
            asset_standard=transfer["asset_standard"],
            event_type=transfer["event_type"],
            token_id=transfer.get("token_id"),
            timestamp=transfer["block_timestamp"],
            tx_hash=transfer["tx_hash"],
            tx_hashes=[transfer["tx_hash"]],
            transfer_count=1,
        )
        visible_graph.add_edge(
            tx_node_id,
            target_wallet,
            weight=float(transfer["amount"]),
            kind="transaction_to_wallet",
            token=transfer["token_symbol"],
            asset_standard=transfer["asset_standard"],
            event_type=transfer["event_type"],
            token_id=transfer.get("token_id"),
            timestamp=transfer["block_timestamp"],
            tx_hash=transfer["tx_hash"],
            tx_hashes=[transfer["tx_hash"]],
            transfer_count=1,
        )

        wallet_nodes_added.add(source_wallet)
        wallet_nodes_added.add(target_wallet)

    annotate_visible_wallets(visible_graph, suspicious_wallets, anomalies, report)
    if not visible_graph.nodes:
        for node in suspicious_wallets:
            add_wallet_node(visible_graph, graph, node, suspicious_wallets)
            annotate_visible_wallets(visible_graph, suspicious_wallets, anomalies, report)
    return visible_graph


def collect_suspicious_wallets(graph: nx.DiGraph, anomalies: list[AnomalyFinding], report: UseCaseReport) -> set[str]:
    suspicious_wallets: set[str] = set()
    for node, data in graph.nodes(data=True):
        risk_score = float(data.get("risk_score", 0.0))
        tags = set(data.get("tags", []))
        if risk_score >= 0.5 or tags.intersection({"anomaly_path", "dispersal_hub", "collector_wallet", "liquidity_pool_candidate", "swap_router_candidate", "exchange_candidate"}):
            suspicious_wallets.add(node)
    for finding in anomalies:
        if finding.node:
            suspicious_wallets.add(finding.node)
        suspicious_wallets.update(finding.path)
    for role in report.protocol_roles:
        suspicious_wallets.add(role.address)
    return suspicious_wallets


def add_wallet_node(
    visible_graph: nx.MultiDiGraph,
    source_graph: nx.DiGraph,
    wallet: str,
    suspicious_wallets: set[str],
) -> None:
    if wallet in visible_graph:
        return
    source_data = source_graph.nodes[wallet] if wallet in source_graph else {}
    role = source_data.get("role")
    tags = sorted(set(source_data.get("tags", [])))
    visible_graph.add_node(
        wallet,
        label=short_address(wallet),
        kind="wallet",
        subtitle=role_to_subtitle(role, tags),
        detail=wallet_detail(source_data),
        total_in=float(source_data.get("total_in", 0.0)),
        total_out=float(source_data.get("total_out", 0.0)),
        role=role,
        tags=tags + (["suspicious"] if wallet in suspicious_wallets else []),
        risk_score=float(source_data.get("risk_score", 0.0)),
        tx_hashes=list(source_data.get("tx_hashes", [])),
        report_hint=wallet_report_hint(source_data, wallet in suspicious_wallets),
    )


def add_tx_node(
    visible_graph: nx.MultiDiGraph,
    transfer: dict[str, object],
    tx_node_id: str,
    source_wallet: str,
    target_wallet: str,
) -> None:
    if tx_node_id in visible_graph:
        return
    amount = float(transfer["amount"])
    token_symbol = str(transfer["token_symbol"])
    block_number = int(transfer["block_number"])
    block_timestamp = int(transfer["block_timestamp"])
    visible_graph.add_node(
        tx_node_id,
        label=short_tx_hash(str(transfer["tx_hash"])),
        kind="transaction",
        subtitle=f"{amount:,.6f} {token_symbol}",
        detail=f"{source_wallet} -> {target_wallet}",
        total_in=amount,
        total_out=amount,
        role="transaction",
        tags=["transaction", "cctv"],
        risk_score=0.25,
        tx_hashes=[str(transfer["tx_hash"])],
        report_hint=f"Tx {short_tx_hash(str(transfer['tx_hash']))} at block {block_number}",
    )


def annotate_visible_wallets(
    visible_graph: nx.MultiDiGraph,
    suspicious_wallets: set[str],
    anomalies: list[AnomalyFinding],
    report: UseCaseReport,
) -> None:
    anomaly_lookup = build_anomaly_lookup(anomalies)
    for node, data in visible_graph.nodes(data=True):
        if data.get("kind") != "wallet":
            continue
        wallet = str(node)
        data["report_hint"] = pick_wallet_hint(wallet, data, anomaly_lookup, report)
        if wallet in suspicious_wallets:
            data["tags"] = sorted(set(data.get("tags", [])) | {"suspicious"})
            data["risk_score"] = max(float(data.get("risk_score", 0.0)), 0.85)


def build_anomaly_lookup(anomalies: list[AnomalyFinding]) -> dict[str, list[AnomalyFinding]]:
    lookup: dict[str, list[AnomalyFinding]] = {}
    for finding in anomalies:
        if finding.node:
            lookup.setdefault(finding.node.lower(), []).append(finding)
        for address in finding.path:
            lookup.setdefault(address.lower(), []).append(finding)
    return lookup


def wallet_report_hint(
    source_data: dict[str, object],
    suspicious: bool,
) -> str:
    role = source_data.get("role")
    if suspicious and role:
        return f"Suspicious {role}"
    if suspicious:
        return "Suspicious wallet"
    return "Context wallet"


def pick_wallet_hint(
    wallet: str,
    data: dict[str, object],
    anomaly_lookup: dict[str, list[AnomalyFinding]],
    report: UseCaseReport,
) -> str:
    if wallet.lower() in anomaly_lookup:
        finding = anomaly_lookup[wallet.lower()][0]
        return finding.description
    role = data.get("role")
    if role:
        return f"{role_to_subtitle(role, data.get('tags', []))} wallet"
    if report.highlights:
        return report.highlights[0]
    return "Investigative clue node"


def role_to_subtitle(role: object, tags: Iterable[str]) -> str | None:
    if not role:
        return "Context"
    role_text = str(role)
    if role_text == "exchange_candidate":
        return "Exchange touchpoint"
    if role_text == "dispersal_hub":
        return "Dispersal hub"
    if role_text == "collector_wallet":
        return "Collector wallet"
    if role_text == "liquidity_pool_candidate":
        return "Liquidity pool"
    if role_text == "swap_router_candidate":
        return "Router"
    if "cctv" in tags:
        return "Transaction node"
    return role_text.replace("_", " ").title()


def wallet_detail(source_data: dict[str, object]) -> str:
    total_in = float(source_data.get("total_in", 0.0))
    total_out = float(source_data.get("total_out", 0.0))
    return f"In {total_in:,.4f} | Out {total_out:,.4f}"


def transaction_node_id(tx_hash: str, log_index: int) -> str:
    return f"tx:{tx_hash}:{log_index}"


def collect_fallback_transfers(
    graph: nx.DiGraph,
    suspicious_wallets: set[str],
) -> list[dict[str, object]]:
    transfers: list[dict[str, object]] = []
    for source, target, data in graph.edges(data=True):
        if source in suspicious_wallets or target in suspicious_wallets:
            for transfer in data.get("transfers", []):
                transfers.append(transfer)
    return transfers


def top_wallets_by_risk(
    graph: nx.DiGraph,
    *,
    limit: int,
    allowed: set[str] | None = None,
) -> list[str]:
    candidates = list(allowed) if allowed else list(graph.nodes)
    ranked = sorted(
        candidates,
        key=lambda node: (
            float(graph.nodes[node].get("risk_score", 0.0)) if node in graph else 0.0,
            float(graph.nodes[node].get("total_in", 0.0)) + float(graph.nodes[node].get("total_out", 0.0)) if node in graph else 0.0,
            graph.in_degree(node) + graph.out_degree(node) if node in graph else 0,
        ),
        reverse=True,
    )
    return ranked[:limit]


def short_address(address: str) -> str:
    if len(address) <= 12:
        return address
    return f"{address[:6]}...{address[-4:]}"


def short_tx_hash(tx_hash: str) -> str:
    if len(tx_hash) <= 12:
        return tx_hash
    return f"{tx_hash[:8]}...{tx_hash[-6:]}"
