# WORKLOG — Threat Guard (Teneo agent)

Project folder: `/home/deva/teneo-agents/threat-guard/`
Started: 2026-10-11 (WIB)
Status: **code complete, unit + live integration tested, ready to deploy**

---

## Purpose

A paid query agent on the Teneo network for EVM security screening:
address risk, phishing domain checks and full flag breakdowns.

Distinct from the existing `signal-radar-pro` agent, which uses DexScreener
+ GoPlus `token_security`. This one uses three different GoPlus endpoints
(`address_security`, `phishing_site`) so the two agents do not overlap.

---

## Commands

| Command | Args | Price | Notes |
|:--|:--|:--|:--|
| `help` | — | free | 1089-char help text |
| `wallet <chain> <address>` | chain + 0x addr | $0.005 | plain-text risk report |
| `site <domain-or-url>` | domain/URL | $0.003 | phishing verdict |
| `flags <chain> <address>` | chain + 0x addr | $0.01 | full raw JSON |

Chains: ethereum, bsc, base, polygon, avalanche (+ raw numeric ids).

---

## Data source

GoPlus Labs Security API, free tier, no key:

- `GET /api/v1/address_security/{address}?chain_id={id}`
- `GET /api/v1/phishing_site?url={target}`

In-memory cache, 5-minute TTL, to stay under the free rate limit.

### API format pitfall (cost 20 min)

The docs page renders as `/address_security/{chainId}?address=` which
looks symmetric with `token_security`. It is **not**. The real form is:

```
/api/v1/address_security/{address}?chain_id={id}
```

Address goes in the **PATH**, chain_id is the **query parameter**. The
wrong form returns `{"code":5006,"message":"Param error!"}` — which
looks exactly like a rate-limit or transient failure. Confirmed correct
by reading the OpenAPI block in
`docs.gopluslabs.io/reference/addresscontractusingget_1.md`.

**Lesson:** when a "free" API returns a generic param error on a request
that previously worked, read the OpenAPI definition instead of assuming
rate limiting.

---

## Verification done

- Go 1.24.7 at `~/go-toolchain` (user-local, no sudo).
- `gofmt` clean, `go vet` clean, `go build` clean.
- `go test ./...` — 8/8 unit tests pass (flag logic, chain resolution,
  address validation).
- Live integration harness (temporary, removed after run) exercised all
  four commands against the real GoPlus API:
  - `wallet ethereum 0xd8da6bf...` → CLEAN, contract_address detected
  - `site uniswap.org` → not flagged
  - `flags base 0x8335...` (USDC) → full JSON, 20 flags, is_contract true
  - `wallet ethereum 0xnotanaddress` → clean rejection message
  - `help` → renders

Bugs found and fixed during verification:

1. `declared and not used: sorted` in `rawFlags` — dead ordering code,
   removed (caught by `go vet`, not by the compiler alone on the first pass).
2. Wrong `address_security` URL form (above) — the real blocker.

---

## Not yet done

- `.env` with `PRIVATE_KEY` — needs devan to supply the wallet key.
- `teneo agent validate threat-guard-metadata.json`.
- `teneo agent deploy ./threat-guard` (mints NFT, gasless).
- `teneo agent publish threat-guard` (public review, up to 72h).

## Known blocker from the previous agent

`signal-radar-pro` is stuck on a Teneo backend IPFS 403 during metadata
upload (Pinata). If that backend fault is still active, this agent will
hit the same mint-finalization failure. Retry and see.
