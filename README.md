# Smart Contract Flow Analyzer (Tool B)

FastAPI + Web3.py backend and vanilla D3.js frontend for forensic ERC-20 transfer flow analysis.

## Run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:ETHEREUM_RPC_URL="https://your-archive-node.example"
$env:ETHERSCAN_API_KEY="optional-api-key"
$env:CACHE_TTL_SECONDS="900"
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`.

## API

```text
GET /api/analyze?target=0x...&from_block=19000000&to_block=latest&max_depth=1
POST /api/analyze
```

The analyzer follows the required pipeline:

1. Web3.py Transfer log ingestion.
2. ABI-aware signature fallback decoding.
3. NetworkX directed graph construction.
4. Peeling chain and splitter/mixer heuristics.
5. D3 Sankey JSON serialization.

Local analysis responses are persisted to `data/analyzer_cache.sqlite3` by default. Set `CACHE_ENABLED=false` to disable write-through caching or `PERSISTENCE_PATH` to relocate the SQLite file.
