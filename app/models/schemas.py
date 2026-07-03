from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator


ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
TX_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")
AnalysisProfile = Literal["defi_audit", "incident_response", "compliance_reporting"]


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=42, max_length=66)
    from_block: int = Field(ge=0)
    to_block: int | Literal["latest"] = "latest"
    max_depth: int = Field(default=1, ge=0, le=4)
    narrow_block_window: int = Field(default=2, ge=0, le=100)
    analysis_profile: AnalysisProfile = "incident_response"
    use_cache: bool = True
    incident_started_at: datetime | None = None
    complaint_received_at: datetime | None = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        if ADDRESS_RE.match(value) or TX_HASH_RE.match(value):
            return value
        raise ValueError("target must be a 20-byte Ethereum address or 32-byte transaction hash")

    @field_validator("to_block", mode="before")
    @classmethod
    def validate_to_block(cls, value: object) -> int | Literal["latest"]:
        if value == "latest":
            return "latest"
        if isinstance(value, str) and value.isdigit():
            return int(value)
        if isinstance(value, int):
            return value
        raise ValueError("to_block must be an integer block number or 'latest'")

    @computed_field
    @property
    def target_type(self) -> Literal["address", "transaction"]:
        return "transaction" if TX_HASH_RE.match(self.target) else "address"


class TokenMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_address: str
    symbol: str
    decimals: int = Field(default=18, ge=0, le=255)


class DecodedTransferEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_address: str
    event_type: Literal["erc20_transfer", "erc721_transfer"]
    asset_standard: Literal["ERC20", "ERC721"]
    from_address: str
    to_address: str
    value_raw: int = Field(ge=0)
    amount: float = Field(ge=0)
    token_symbol: str
    decimals: int = Field(ge=0, le=255)
    token_id: int | None = None
    block_number: int = Field(ge=0)
    block_timestamp: int = Field(ge=0)
    tx_hash: str
    log_index: int = Field(ge=0)
    depth: int = Field(default=0, ge=0, le=4)


class GraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    total_in: float = 0.0
    total_out: float = 0.0
    role: str | None = None
    tags: list[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


class GraphLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: int
    target: int
    value: float = Field(ge=0)
    tx_hash: str
    tx_hashes: list[str] = Field(default_factory=list)
    token: str
    asset_standard: str = ""
    event_type: str = ""
    token_id: int | None = None
    timestamp: int | None = None
    transfer_count: int = Field(default=1, ge=1)


class AnomalyFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["peeling_chain", "splitter_mixer"]
    severity: Literal["low", "medium", "high"]
    description: str
    node: str | None = None
    path: list[str] = Field(default_factory=list)
    tx_hashes: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class ProtocolRoleFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str
    role: Literal[
        "swap_router_candidate",
        "liquidity_pool_candidate",
        "dispersal_hub",
        "collector_wallet",
        "exchange_candidate",
        "bridge_candidate",
    ]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)


class UseCaseReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: AnalysisProfile
    title: str
    summary: str
    key_metrics: dict[str, Any] = Field(default_factory=dict)
    highlights: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    protocol_roles: list[ProtocolRoleFinding] = Field(default_factory=list)


class AnalysisMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    target_type: Literal["address", "transaction"]
    analysis_profile: AnalysisProfile
    from_block: int
    to_block: int | Literal["latest"]
    max_depth: int
    raw_log_count: int
    decoded_event_count: int
    graph_node_count: int
    graph_link_count: int
    full_graph_node_count: int = 0
    full_graph_link_count: int = 0
    visible_graph_node_count: int = 0
    visible_graph_link_count: int = 0
    cache_status: Literal["disabled", "hit", "miss"] = "disabled"
    timeline_start_at: datetime | None = None
    timeline_end_at: datetime | None = None
    warnings: list[str] = Field(default_factory=list)


class SankeyPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nodes: list[GraphNode]
    links: list[GraphLink]
    anomalies: list[AnomalyFinding]
    report: UseCaseReport
    metadata: AnalysisMetadata
