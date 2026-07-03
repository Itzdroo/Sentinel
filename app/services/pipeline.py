from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.config import Settings
from app.core.exceptions import AnalyzerError, DecodeError
from app.models.schemas import AnalysisMetadata, AnalyzeRequest, DecodedTransferEvent, SankeyPayload
from app.services.decoder import TransferDecoder
from app.services.etherscan import EtherscanClient
from app.services.graph_builder import GraphConstructionFactory
from app.services.heuristics import ForensicsHeuristicsEngine
from app.services.ingestion import IngestionEngine
from app.services.persistence import AnalysisCache, provider_fingerprint
from app.services.reporting import UseCaseReportBuilder
from app.services.serializer import D3PayloadSerializer
from app.services.web3_client import EthereumClient


class FlowAnalyzer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.ethereum = EthereumClient(settings)
        self.provider_fingerprint = provider_fingerprint(settings.ethereum_rpc_url)
        self.cache = AnalysisCache(settings.persistence_path, ttl_seconds=settings.cache_ttl_seconds)
        self.etherscan = EtherscanClient(
            api_key=settings.etherscan_api_key,
            base_url=settings.etherscan_base_url,
            calls_per_second=settings.etherscan_calls_per_second,
        )
        self.ingestion = IngestionEngine(self.ethereum)
        self.decoder = TransferDecoder()
        self.graph_factory = GraphConstructionFactory()
        self.heuristics = ForensicsHeuristicsEngine()
        self.report_builder = UseCaseReportBuilder()
        self.serializer = D3PayloadSerializer()

    def analyze(self, request: AnalyzeRequest) -> SankeyPayload:
        if self.settings.cache_enabled and request.use_cache:
            cached = self.cache.get(request, provider_fingerprint=self.provider_fingerprint)
            if cached is not None:
                return cached

        self.ethereum.ensure_connected()

        ingestion_result = self.ingestion.fetch(request)
        decoded_events: list[DecodedTransferEvent] = []
        warnings = list(ingestion_result.warnings)

        for raw_log in ingestion_result.raw_logs:
            try:
                block_timestamp = self.ethereum.get_block_timestamp(int(raw_log["blockNumber"]))
                token_metadata = self.ethereum.get_token_metadata(raw_log["address"])
                explicit_abi = self._safe_contract_abi(raw_log["address"], warnings)
                decoded_event = self.decoder.decode(
                    raw_log,
                    token_metadata=token_metadata,
                    block_timestamp=block_timestamp,
                    explicit_abi=explicit_abi,
                )
                if self._within_timeline(request, decoded_event.block_timestamp):
                    decoded_events.append(decoded_event)
            except DecodeError as exc:
                if len(warnings) < 25:
                    warnings.append(f"decode skipped at log {raw_log.get('transactionHash')}:{raw_log.get('logIndex')}: {exc.message}")

        graph = self.graph_factory.build(decoded_events, max_depth=request.max_depth)
        anomalies = self.heuristics.analyze(
            graph,
            decoded_events,
            narrow_block_window=request.narrow_block_window,
        )
        report = self.report_builder.build(
            graph,
            decoded_events,
            anomalies,
            profile=request.analysis_profile,
        )
        metadata = AnalysisMetadata(
            target=request.target,
            target_type=request.target_type,
            analysis_profile=request.analysis_profile,
            from_block=request.from_block,
            to_block=request.to_block,
            max_depth=min(request.max_depth, 4),
            raw_log_count=len(ingestion_result.raw_logs),
            decoded_event_count=len(decoded_events),
            graph_node_count=graph.number_of_nodes(),
            graph_link_count=graph.number_of_edges(),
            full_graph_node_count=graph.number_of_nodes(),
            full_graph_link_count=graph.number_of_edges(),
            cache_status="miss" if self.settings.cache_enabled and request.use_cache else "disabled",
            timeline_start_at=request.incident_started_at,
            timeline_end_at=request.complaint_received_at,
            warnings=warnings,
        )
        payload = self.serializer.serialize(graph, anomalies=anomalies, report=report, metadata=metadata)
        if self.settings.cache_enabled and request.use_cache:
            self.cache.set(request, payload, provider_fingerprint=self.provider_fingerprint)
        return payload

    def _safe_contract_abi(self, contract_address: str, warnings: list[str]) -> list[dict] | None:
        try:
            return self.etherscan.get_contract_abi(contract_address)
        except AnalyzerError as exc:
            warning = f"ABI lookup skipped for {contract_address}: {exc.message}"
            if warning not in warnings and len(warnings) < 25:
                warnings.append(warning)
            return None

    @staticmethod
    def _within_timeline(request: AnalyzeRequest, block_timestamp: int) -> bool:
        start = request.incident_started_at
        end = request.complaint_received_at
        if start is None and end is not None:
            start = end - timedelta(hours=48)
        if start is None and end is None:
            return True
        timestamp = datetime.fromtimestamp(block_timestamp, tz=timezone.utc)
        start = PipelineDateTime.normalize(start) if start is not None else None
        end = PipelineDateTime.normalize(end) if end is not None else None
        if start is not None and timestamp < start:
            return False
        if end is not None and timestamp > end:
            return False
        return True


class PipelineDateTime:
    @staticmethod
    def normalize(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
