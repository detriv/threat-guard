# Threat Guard

EVM address, domain and phishing security screening agent for the
[Teneo](https://teneo-protocol.ai) network.

Screens any wallet or contract address for scam and sanctions exposure
(cybercrime, money laundering, mixer use, malicious contracts created,
phishing activity), verifies whether a domain is a known phishing site,
and returns a full raw-flag breakdown on demand.

Built with the [Teneo Agent SDK](https://github.com/TeneoProtocolAI/teneo-agent-sdk) (v0.9.1).

## Commands

| Command | Args | Price | What it returns |
|:--|:--|:--|:--|
| `help` | — | free | Command list with examples and pricing |
| `wallet <chain> <address>` | chain + 0x address | $0.005 | Risk verdict (HIGH/MEDIUM/LOW/CLEAN) + raised flags |
| `site <domain-or-url>` | domain or URL | $0.003 | Phishing verdict + related flagged contracts |
| `flags <chain> <address>` | chain + 0x address | $0.01 | Full raw JSON: every GoPlus flag with its value |

Supported chains: `ethereum`, `bsc`, `base`, `polygon`, `avalanche`
(raw numeric chain ids also accepted).

## Data source

[GoPlus Labs Security API](https://docs.gopluslabs.io) — free tier, no API
key required. Two endpoints:

- `GET /api/v1/address_security/{address}?chain_id={id}`
- `GET /api/v1/phishing_site?url={target}`

Responses are cached in memory for 5 minutes to stay inside the free
rate limit.

## Build

Requires Go 1.24+ (user-local install at `~/go-toolchain` works).

```bash
cd ~/teneo-agents/threat-guard
export PATH="$HOME/go-toolchain/bin:$PATH"
go mod tidy
go build -o threat-guard .
go vet ./...
go test ./...
```

## Run

```bash
cp .env.example .env
# fill in PRIVATE_KEY
ACCEPT_EULA=true ./threat-guard
```

On first run without `NFT_TOKEN_ID` the SDK mints a gasless NFT identity
via the Teneo backend. Put the returned token id in `.env` for subsequent
runs.

Health endpoints (default port 8091):

```bash
curl http://localhost:8091/health
curl http://localhost:8091/status
```

## Deploy to Teneo

```bash
teneo agent validate threat-guard-metadata.json
teneo agent deploy ./threat-guard
teneo agent publish threat-guard
```

Metadata: `threat-guard-metadata.json` — 4 commands, 5 capabilities,
`metadata_version` 2.4.0, categories Crypto + Other. Pricing uses the
`task-transaction` / `per-query` shape that the Teneo validator accepts
(the earlier `flat` / `query` values were rejected).

Pricing:

| Command | Args | Price |
|:--|:--|:--|
| `help` | — | free |
| `wallet <chain> <address>` | chain + 0x addr | $0.005 |
| `site <domain-or-url>` | domain/URL | $0.003 |
| `flags <chain> <address>` | chain + 0x addr | $0.01 |

## Verify before trusting a result

The `site` and `wallet` commands only reflect the GoPlus database. A clean
result is not proof a target is safe. Use `flags` to see the raw values
and judge severity yourself.

## Project layout

```
threat-guard/
├── main.go                        # task handler + command routing + main()
├── api.go                         # GoPlus client, caching, flag interpretation
├── main_test.go                   # unit tests (flag logic, validation)
├── threat-guard-metadata.json     # deploy metadata (commands, pricing)
├── go.mod / go.sum
├── .env.example
└── WORKLOG.md
```
