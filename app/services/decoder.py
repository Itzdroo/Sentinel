from __future__ import annotations

from decimal import Decimal
from typing import Any

from web3 import Web3

from app.core.exceptions import DecodeError
from app.models.schemas import DecodedTransferEvent, TokenMetadata
from app.services.web3_client import TRANSFER_TOPIC, normalize_hex


class TransferDecoder:
    def decode(
        self,
        raw_log: dict[str, Any],
        *,
        token_metadata: TokenMetadata,
        block_timestamp: int,
        explicit_abi: list[dict[str, Any]] | None = None,
    ) -> DecodedTransferEvent:
        topics = [normalize_hex(topic) for topic in raw_log.get("topics", [])]
        if not topics or topics[0].lower() != TRANSFER_TOPIC:
            raise DecodeError("Log is not an ERC-20 Transfer event")

        decoded = self._decode_with_explicit_abi(topics, raw_log, explicit_abi)
        if decoded is None:
            decoded = self._decode_with_signature_fallback(topics, raw_log)

        value_raw = decoded["value_raw"]
        if decoded["asset_standard"] == "ERC721":
            amount = 1.0
        else:
            amount = float(Decimal(value_raw) / (Decimal(10) ** token_metadata.decimals))
        return DecodedTransferEvent(
            contract_address=Web3.to_checksum_address(raw_log["address"]),
            event_type=decoded["event_type"],
            asset_standard=decoded["asset_standard"],
            from_address=decoded["from_address"],
            to_address=decoded["to_address"],
            value_raw=value_raw,
            amount=amount,
            token_symbol=token_metadata.symbol,
            decimals=token_metadata.decimals,
            token_id=decoded.get("token_id"),
            block_number=int(raw_log["blockNumber"]),
            block_timestamp=block_timestamp,
            tx_hash=normalize_hex(raw_log["transactionHash"]),
            log_index=int(raw_log["logIndex"]),
            depth=int(raw_log.get("analysisDepth", 0)),
        )

    def _decode_with_explicit_abi(
        self,
        topics: list[str],
        raw_log: dict[str, Any],
        explicit_abi: list[dict[str, Any]] | None,
    ) -> dict[str, Any] | None:
        if not explicit_abi:
            return None
        transfer_event = next(
            (
                item
                for item in explicit_abi
                if item.get("type") == "event" and item.get("name") == "Transfer" and not item.get("anonymous", False)
            ),
            None,
        )
        if not transfer_event:
            return None
        inputs = transfer_event.get("inputs", [])
        indexed = [item for item in inputs if item.get("indexed")]
        unindexed = [item for item in inputs if not item.get("indexed")]
        if len(indexed) < 2:
            return None
        is_erc721 = len(indexed) >= 3 and len(topics) >= 4 and normalized_data(raw_log.get("data", "0x")) in {"", "0x"}
        if indexed[0].get("type") != "address" or indexed[1].get("type") != "address":
            return None

        if is_erc721:
            return {
                "event_type": "erc721_transfer",
                "asset_standard": "ERC721",
                "from_address": topic_to_address(topics[1]),
                "to_address": topic_to_address(topics[2]),
                "value_raw": 1,
                "token_id": topic_to_uint256(topics[3]),
            }

        if not unindexed or unindexed[0].get("type") not in {"uint256", "uint"}:
            return None
        return {
            "event_type": "erc20_transfer",
            "asset_standard": "ERC20",
            "from_address": topic_to_address(topics[1]),
            "to_address": topic_to_address(topics[2]),
            "value_raw": decode_uint256(raw_log.get("data", "0x")),
            "token_id": None,
        }

    def _decode_with_signature_fallback(self, topics: list[str], raw_log: dict[str, Any]) -> dict[str, Any]:
        if len(topics) < 3:
            raise DecodeError("Transfer log is missing indexed from/to topics", details={"topics": topics})
        data = normalized_data(raw_log.get("data", "0x"))
        if len(topics) >= 4 and data in {"", "0x"}:
            return {
                "event_type": "erc721_transfer",
                "asset_standard": "ERC721",
                "from_address": topic_to_address(topics[1]),
                "to_address": topic_to_address(topics[2]),
                "value_raw": 1,
                "token_id": topic_to_uint256(topics[3]),
            }
        return {
            "event_type": "erc20_transfer",
            "asset_standard": "ERC20",
            "from_address": topic_to_address(topics[1]),
            "to_address": topic_to_address(topics[2]),
            "value_raw": decode_uint256(raw_log.get("data", "0x")),
            "token_id": None,
        }


def topic_to_address(topic: str) -> str:
    normalized = normalize_hex(topic).removeprefix("0x")
    if len(normalized) != 64:
        raise DecodeError("Address topic must be 32 bytes", details={"topic": topic})
    return Web3.to_checksum_address("0x" + normalized[-40:])


def topic_to_uint256(topic: str) -> int:
    normalized = normalize_hex(topic).removeprefix("0x")
    if len(normalized) != 64:
        raise DecodeError("Token id topic must be 32 bytes", details={"topic": topic})
    try:
        return int(normalized, 16)
    except ValueError as exc:
        raise DecodeError("Token id topic is not valid hex", details={"topic": topic}) from exc


def normalized_data(data: Any) -> str:
    return normalize_hex(data).lower()


def decode_uint256(data: Any) -> int:
    normalized = normalize_hex(data).removeprefix("0x")
    if not normalized:
        raise DecodeError("Transfer data is empty; ERC-20 value payload is required")
    if len(normalized) > 64:
        normalized = normalized[:64]
    try:
        return int(normalized, 16)
    except ValueError as exc:
        raise DecodeError("Transfer value payload is not valid hex", details={"data": normalize_hex(data)}) from exc
