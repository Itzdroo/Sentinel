from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from web3 import Web3

from app.core.config import Settings
from app.core.exceptions import RpcConnectionError, RpcQueryError
from app.models.schemas import TokenMetadata
from app.services.backoff import is_retryable_message, retry_with_backoff


TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ERC721_TRANSFER_TOPIC = TRANSFER_TOPIC

ERC20_STRING_ABI: list[dict[str, Any]] = [
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    },
]

ERC20_BYTES32_SYMBOL_ABI: list[dict[str, Any]] = [
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "bytes32"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    }
]

ERC721_NAME_ABI: list[dict[str, Any]] = [
    {
        "constant": True,
        "inputs": [],
        "name": "name",
        "outputs": [{"name": "", "type": "string"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    }
]


class EthereumClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        provider = Web3.HTTPProvider(
            settings.ethereum_rpc_url,
            request_kwargs={"timeout": settings.rpc_timeout_seconds},
        )
        self.w3 = Web3(provider)
        self._timestamp_cache: dict[int, int] = {}
        self._token_cache: dict[str, TokenMetadata] = {}

    def ensure_connected(self) -> None:
        try:
            connected = self.w3.is_connected()
        except Exception as exc:
            raise RpcConnectionError("Could not reach Ethereum RPC provider", details={"error": str(exc)}) from exc
        if not connected:
            raise RpcConnectionError("Ethereum RPC provider is not connected")

    def checksum_address(self, address: str) -> str:
        try:
            return Web3.to_checksum_address(address)
        except Exception as exc:
            raise RpcQueryError("Invalid Ethereum address", details={"address": address}) from exc

    def resolve_block_range(self, from_block: int, to_block: int | str) -> tuple[int, int]:
        if to_block == "latest":
            latest = self._rpc_call(lambda: self.w3.eth.block_number, "fetch latest block number")
            end_block = int(latest)
        else:
            end_block = int(to_block)
        if end_block < from_block:
            raise RpcQueryError(
                "to_block must be greater than or equal to from_block",
                details={"from_block": from_block, "to_block": end_block},
            )
        return from_block, end_block

    def get_transfer_logs_for_contract(self, contract_address: str, from_block: int, to_block: int) -> list[dict[str, Any]]:
        return self.get_logs(
            from_block=from_block,
            to_block=to_block,
            filter_address=self.checksum_address(contract_address),
            topics=[TRANSFER_TOPIC],
        )

    def get_transfer_logs_for_participant(self, participant_address: str, from_block: int, to_block: int) -> list[dict[str, Any]]:
        topic_address = address_to_topic(self.checksum_address(participant_address))
        outgoing = self.get_logs(from_block=from_block, to_block=to_block, topics=[TRANSFER_TOPIC, topic_address, None])
        incoming = self.get_logs(from_block=from_block, to_block=to_block, topics=[TRANSFER_TOPIC, None, topic_address])
        merged: dict[tuple[str, int], dict[str, Any]] = {}
        for log in outgoing + incoming:
            key = (self.log_tx_hash(log), int(log.get("logIndex", 0)))
            merged[key] = log
        return sorted(merged.values(), key=lambda item: (int(item.get("blockNumber", 0)), int(item.get("logIndex", 0))))

    def get_transfer_logs_for_transaction(self, tx_hash: str) -> list[dict[str, Any]]:
        receipt = self._rpc_call(lambda: self.w3.eth.get_transaction_receipt(tx_hash), "fetch transaction receipt")
        logs = []
        for log in receipt.get("logs", []):
            topics = [normalize_hex(topic) for topic in log.get("topics", [])]
            if topics and topics[0].lower() == TRANSFER_TOPIC:
                logs.append(normalize_log(log))
        return sorted(logs, key=lambda item: int(item.get("logIndex", 0)))

    def get_logs(
        self,
        *,
        from_block: int,
        to_block: int,
        topics: list[str | None],
        filter_address: str | None = None,
    ) -> list[dict[str, Any]]:
        logs: list[dict[str, Any]] = []
        for start, end in self._block_chunks(from_block, to_block):
            params: dict[str, Any] = {
                "fromBlock": start,
                "toBlock": end,
                "topics": topics,
            }
            if filter_address is not None:
                params["address"] = filter_address
            chunk = self._rpc_call(lambda: self.w3.eth.get_logs(params), "fetch transfer logs")
            logs.extend(normalize_log(log) for log in chunk)
        return logs

    def get_block_timestamp(self, block_number: int) -> int:
        if block_number in self._timestamp_cache:
            return self._timestamp_cache[block_number]
        block = self._rpc_call(lambda: self.w3.eth.get_block(block_number), "fetch block timestamp")
        timestamp = int(block.get("timestamp", 0))
        self._timestamp_cache[block_number] = timestamp
        return timestamp

    def get_token_metadata(self, contract_address: str) -> TokenMetadata:
        checksum = self.checksum_address(contract_address)
        cache_key = checksum.lower()
        if cache_key in self._token_cache:
            return self._token_cache[cache_key]

        symbol = self._read_symbol(checksum) or f"TKN-{checksum[2:8]}"
        decimals = self._read_decimals(checksum)
        metadata = TokenMetadata(contract_address=checksum, symbol=symbol, decimals=decimals)
        self._token_cache[cache_key] = metadata
        return metadata

    def _read_symbol(self, contract_address: str) -> str | None:
        contract = self.w3.eth.contract(address=contract_address, abi=ERC20_STRING_ABI)
        try:
            value = self._rpc_call(lambda: contract.functions.symbol().call(), "read token symbol")
        except Exception:
            bytes_contract = self.w3.eth.contract(address=contract_address, abi=ERC20_BYTES32_SYMBOL_ABI)
            try:
                value = self._rpc_call(lambda: bytes_contract.functions.symbol().call(), "read token bytes32 symbol")
            except Exception:
                return None
        if isinstance(value, bytes):
            return value.rstrip(b"\x00").decode("utf-8", errors="ignore") or None
        return str(value)[:32] if value is not None else None

    def _read_decimals(self, contract_address: str) -> int:
        contract = self.w3.eth.contract(address=contract_address, abi=ERC20_STRING_ABI)
        try:
            value = self._rpc_call(lambda: contract.functions.decimals().call(), "read token decimals")
            decimals = int(value)
            return decimals if 0 <= decimals <= 255 else 18
        except Exception:
            return 18

    def _block_chunks(self, from_block: int, to_block: int) -> Iterable[tuple[int, int]]:
        chunk_size = self.settings.block_chunk_size
        start = from_block
        while start <= to_block:
            end = min(to_block, start + chunk_size - 1)
            yield start, end
            start = end + 1

    def _rpc_call(self, operation: Any, action: str) -> Any:
        try:
            return retry_with_backoff(operation, should_retry=lambda exc: is_retryable_message(str(exc)))
        except Exception as exc:
            raise RpcQueryError(f"RPC failed while attempting to {action}", details={"error": str(exc)}) from exc

    @staticmethod
    def log_tx_hash(log: dict[str, Any]) -> str:
        return normalize_hex(log.get("transactionHash", "0x"))


def normalize_log(log: Any) -> dict[str, Any]:
    item = dict(log)
    item["address"] = normalize_hex(item.get("address", "0x"))
    item["topics"] = [normalize_hex(topic) for topic in item.get("topics", [])]
    item["data"] = normalize_hex(item.get("data", "0x"))
    item["transactionHash"] = normalize_hex(item.get("transactionHash", "0x"))
    item["blockNumber"] = int(item.get("blockNumber", 0))
    item["logIndex"] = int(item.get("logIndex", 0))
    return item


def normalize_hex(value: Any) -> str:
    if isinstance(value, str):
        return value
    if hasattr(value, "hex"):
        text = value.hex()
        return text if text.startswith("0x") else f"0x{text}"
    if isinstance(value, int):
        return hex(value)
    return str(value)


def address_to_topic(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")
