# Sentinel

Smart Contract Flow Analyzer is a forensic Ethereum MVP that traces ERC-20 and ERC-721 transfers, builds a directed flow graph, flags suspicious wallets, and produces investigator-ready reports.

## What It Does

- Ingests historical logs from an Ethereum RPC provider
- Decodes transfer events with ABI-aware fallback logic
- Builds a NetworkX graph of wallet-to-wallet value flow
- Flags peeling chains, splitter/mixer behavior, and exchange touchpoints
- Renders an interactive D3 Sankey or node-link graph
- Exports a case package as JSON or a print-ready PDF report

## Presentation Highlights

- `FastAPI backend + ERC-20/721 transfer tracing`
- `Suspicious-wallet-first graph view`
- `Incident response, DeFi auditing, and compliance reporting modes`
- `Timeline filtering for complaint-time investigations`
- `Local cache for repeated analyst queries`

## Tech Stack

- Python 3.10+
- FastAPI
- web3.py 6+
- NetworkX 3+
- Pydantic 2
- Vanilla JavaScript
- D3.js 7 + d3-sankey

## Demo Workflow

1. Start the backend.
2. Open the browser at `http://127.0.0.1:8000`.
3. Choose an analysis mode.
4. Enter a target address or transaction hash.
5. Narrow the block range or timeline window.
6. Click `Analyze Flow`.
7. Review the clue graph, report panel, and anomaly flags.
8. Export the case as `JSON` or `PDF`.

## Best Test Inputs

Use a small block window first so the demo stays responsive.

### ERC-20 smoke test

- Target: `0xA0b86991c6218b36c1d19D4a2e9Eb0CE3606EB48`
- From block: `19000000`
- To block: `19000100`
- Mode: `Compliance Reporting`

### WETH smoke test

- Target: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
- From block: `19000000`
- To block: `19000100`
- Mode: `Incident Response`

## Run Locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:ETHEREUM_RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
$env:BLOCK_CHUNK_SIZE="10"
$env:CACHE_TTL_SECONDS="900"
python -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`.

## Run with Docker

Docker Compose keeps the SQLite analysis cache in a named volume and reads RPC configuration from the host environment or a local `.env` file. Never commit `.env` or put provider credentials in the image.

```powershell
$env:ETHEREUM_RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
docker compose up --build
```

Open `http://127.0.0.1:8000`; check `http://127.0.0.1:8000/api/health` for the container health endpoint. Stop the service with `Ctrl+C`, then run `docker compose down` when finished. The named `analyzer-data` volume preserves cached results across container rebuilds.

To set environment variables persistently for Compose, create a local `.env` file from the variable names in `compose.yaml`. Keep that file private; `.env` files are excluded from the Docker build context and Git.

## API

### Health

```text
GET /api/health
```

### Analyze

```text
GET /api/analyze?target=0x...&from_block=19000000&to_block=19000100&analysis_profile=incident_response
POST /api/analyze
```

Query parameters:

- `analysis_profile`: `defi_audit`, `incident_response`, or `compliance_reporting`
- `incident_started_at`: optional ISO timestamp
- `complaint_received_at`: optional ISO timestamp
- `use_cache`: toggle local result caching

## Architecture

1. Ingestion via `web3.eth.get_logs()`
2. ABI/signature decoding for transfer events
3. Graph construction with NetworkX
4. Heuristic analysis for suspicious behavior
5. D3 serialization for the frontend

The shared feature interface in `app/services/feature_store.py` emits deterministic, versioned wallet feature vectors (`sentinel.transfer.v1`) and the same heuristic findings consumed by the visual report. Feature vectors contain descriptive transfer metrics; anomaly labels stay separate so future ML training can choose its own target without label leakage. A future model can consume `FeatureStore.extract_wallet_features(...)` and pin its input contract to `schema_version`.

## Cache and Logs

- Analysis responses are cached in SQLite by normalized request and provider fingerprint, with a configurable TTL. The schema version is part of the cache key, so feature contract changes naturally invalidate older entries.
- Token metadata and block timestamps are cached in memory for the lifetime of a backend process; Etherscan ABI lookups use a process-local cache too.
- SQLite uses WAL mode and a busy timeout for concurrent requests, and successful writes prune expired rows when TTL is enabled.
- Backend request, RPC failure, and finding events are emitted as structured JSON logs. Request logs omit query strings, and RPC log entries omit exception text and provider URLs so API credentials are not copied into logs.

## Output Files

- JSON export includes metadata, report text, anomalies, nodes, and links
- PDF export opens a print-friendly report that the browser can save as PDF

## Local Storage

Cached results are stored in `data/analyzer_cache.sqlite3` by default.

Set these env vars if needed:

- `CACHE_ENABLED=false` to disable caching
- `PERSISTENCE_PATH` to move the SQLite cache
- `ETHERSCAN_API_KEY` to enrich decoding when available

## Notes

- The graph intentionally shows clue nodes first so detectives are not buried in raw wallet noise.
- The timeline filter helps when the complaint arrives long after the fraud window.
- Exchange wallets are flagged across all three reporting modes.
