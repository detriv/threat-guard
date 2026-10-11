package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Upstream API client.
//
// GoPlus Labs Security API — https://docs.gopluslabs.io
//   GET /api/v1/address_security/{chainId}?address={addr}
//   GET /api/v1/phishing_site?url={domain-or-url}
//
// Free tier, no API key required. Rate limits apply, so responses are
// cached for a short window to avoid re-querying the same target.
// ---------------------------------------------------------------------------

const (
	requestTimeout = 30 * time.Second
	userAgent      = "threat-guard/1.0 (teneo-agent)"
	cacheTTL       = 5 * time.Minute
)

var httpClient = &http.Client{Timeout: requestTimeout}

// chainIDMap maps our short chain names to GoPlus numeric chain ids.
var chainIDMap = map[string]int{
	"ethereum":  1,
	"eth":       1,
	"mainnet":   1,
	"bsc":       56,
	"bnb":       56,
	"binance":   56,
	"base":      8453,
	"polygon":   137,
	"matic":     137,
	"avalanche": 43114,
	"avax":      43114,
}

var supportedChains = []string{"ethereum", "bsc", "base", "polygon", "avalanche"}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

// AddressSecurity is the GoPlus address_security payload. Every field is a
// "0"/"1" string; "1" means the flag is present, i.e. the address is exposed.
type AddressSecurity struct {
	Cybercrime                 string `json:"cybercrime"`
	MoneyLaundering            string `json:"money_laundering"`
	NumberOfMaliciousContracts string `json:"number_of_malicious_contracts_created"`
	GasAbuse                   string `json:"gas_abuse"`
	FinancialCrime             string `json:"financial_crime"`
	DarkwebTransactions        string `json:"darkweb_transactions"`
	Reinit                     string `json:"reinit"`
	PhishingActivities         string `json:"phishing_activities"`
	ContractAddress            string `json:"contract_address"`
	FakeKYC                    string `json:"fake_kyc"`
	BlacklistDoubt             string `json:"blacklist_doubt"`
	FakeStandardInterface      string `json:"fake_standard_interface"`
	DataSource                 string `json:"data_source"`
	StealingAttack             string `json:"stealing_attack"`
	BlackmailActivities        string `json:"blackmail_activities"`
	Sanctioned                 string `json:"sanctioned"`
	MaliciousMiningActivities  string `json:"malicious_mining_activities"`
	Mixer                      string `json:"mixer"`
	FakeToken                  string `json:"fake_token"`
	HoneypotRelatedAddress     string `json:"honeypot_related_address"`
}

// PhishingSite is the GoPlus phishing_site payload.
type PhishingSite struct {
	WebsiteContractSecurity []string `json:"website_contract_security"`
	PhishingSite            int      `json:"phishing_site"`
}

// goplusResponse is the standard GoPlus envelope.
type goplusResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Result  json.RawMessage `json:"result"`
}

// ---------------------------------------------------------------------------
// Normalisation helpers
// ---------------------------------------------------------------------------

// flagReport is one human-readable security flag.
type flagReport struct {
	Label    string
	Detail   string
	Severity string // "high", "medium", "info"
}

// raised returns true when a GoPlus "0"/"1" flag is set.
func raised(v string) bool { return strings.TrimSpace(v) == "1" }

// positiveInt returns true when a GoPlus count-style flag is non-zero.
func positiveInt(v string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	return err == nil && n > 0
}

// chainID resolves a chain name or numeric id to a GoPlus chain id.
func chainID(chain string) (int, error) {
	c := strings.ToLower(strings.TrimSpace(chain))
	if c == "" {
		return 0, fmt.Errorf("chain is required")
	}
	if id, ok := chainIDMap[c]; ok {
		return id, nil
	}
	if n, err := strconv.Atoi(c); err == nil && n > 0 {
		return n, nil
	}
	return 0, fmt.Errorf("unsupported chain %q (supported: %s)", chain, strings.Join(supportedChains, ", "))
}

// isAddress does a light sanity check on a 0x address.
func isAddress(addr string) bool {
	a := strings.ToLower(strings.TrimSpace(addr))
	if !strings.HasPrefix(a, "0x") {
		return false
	}
	hex := a[2:]
	if len(hex) != 40 {
		return false
	}
	for _, r := range hex {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

// getJSON fetches url and decodes the GoPlus envelope into out.
func getJSON(url string, out interface{}) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upstream returned HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------------------------------------------------------------------------
// Cached fetchers
// ---------------------------------------------------------------------------

type cacheEntry struct {
	at   time.Time
	body string
}

var cache = map[string]cacheEntry{}

// cachedGet wraps getJSON with a short-lived in-memory cache so repeat
// queries for the same target don't re-hit the upstream rate limit.
func cachedGet(key, url string, out interface{}) error {
	if e, ok := cache[key]; ok && time.Since(e.at) < cacheTTL {
		return json.Unmarshal([]byte(e.body), out)
	}
	if err := getJSON(url, out); err != nil {
		return err
	}
	if b, err := json.Marshal(out); err == nil {
		cache[key] = cacheEntry{at: time.Now(), body: string(b)}
	}
	return nil
}

// fetchAddressSecurity queries GoPlus for one address on one chain.
// Per the GoPlus docs the address goes in the PATH and chain_id is a
// query parameter — /api/v1/address_security/{address}?chain_id={id}.
func fetchAddressSecurity(chainID int, address string) (*AddressSecurity, error) {
	u := fmt.Sprintf(
		"https://api.gopluslabs.io/api/v1/address_security/%s?chain_id=%d",
		strings.ToLower(address), chainID,
	)
	var env goplusResponse
	if err := cachedGet("addr:"+u, u, &env); err != nil {
		return nil, err
	}
	if env.Code != 1 {
		return nil, fmt.Errorf("goplus error code %d: %s", env.Code, env.Message)
	}
	var sec AddressSecurity
	if len(env.Result) == 0 || string(env.Result) == "null" {
		return nil, fmt.Errorf("no security data returned for this address (it may be unindexed on this chain)")
	}
	if err := json.Unmarshal(env.Result, &sec); err != nil {
		return nil, fmt.Errorf("decode security data: %w", err)
	}
	return &sec, nil
}

// fetchPhishingSite queries GoPlus for one domain/URL.
func fetchPhishingSite(target string) (*PhishingSite, error) {
	u := "https://api.gopluslabs.io/api/v1/phishing_site?url=" + url.QueryEscape(target)
	var env goplusResponse
	if err := cachedGet("phish:"+u, u, &env); err != nil {
		return nil, err
	}
	if env.Code != 1 {
		return nil, fmt.Errorf("goplus error code %d: %s", env.Code, env.Message)
	}
	var site PhishingSite
	if len(env.Result) == 0 || string(env.Result) == "null" {
		return nil, fmt.Errorf("no phishing data returned for this target")
	}
	if err := json.Unmarshal(env.Result, &site); err != nil {
		return nil, fmt.Errorf("decode phishing data: %w", err)
	}
	return &site, nil
}

// ---------------------------------------------------------------------------
// Flag interpretation
// ---------------------------------------------------------------------------

// securityFlags turns an AddressSecurity payload into ordered, human-readable
// flags. Order is by severity: high first, then medium, then informational.
func securityFlags(s *AddressSecurity) []flagReport {
	var high, medium, info []flagReport

	if raised(s.Sanctioned) {
		high = append(high, flagReport{"SANCTIONED", "Address appears on a sanctions list", "high"})
	}
	if raised(s.StealingAttack) {
		high = append(high, flagReport{"STEALING ATTACK", "Address associated with a theft/stealing attack", "high"})
	}
	if raised(s.PhishingActivities) {
		high = append(high, flagReport{"PHISHING", "Address flagged for phishing activity", "high"})
	}
	if raised(s.HoneypotRelatedAddress) {
		high = append(high, flagReport{"HONEYPOT RELATED", "Linked to a honeypot token contract", "high"})
	}
	if raised(s.BlackmailActivities) {
		high = append(high, flagReport{"BLACKMAIL", "Address linked to blackmail/extortion activity", "high"})
	}
	if raised(s.MaliciousMiningActivities) {
		high = append(high, flagReport{"MALICIOUS MINING", "Flagged for malicious mining activity", "high"})
	}
	if raised(s.Cybercrime) {
		high = append(high, flagReport{"CYBERCRIME", "Linked to cybercrime", "high"})
	}

	if raised(s.MoneyLaundering) {
		medium = append(medium, flagReport{"MONEY LAUNDERING", "Possible money-laundering exposure", "medium"})
	}
	if raised(s.FinancialCrime) {
		medium = append(medium, flagReport{"FINANCIAL CRIME", "Flagged for financial crime", "medium"})
	}
	if raised(s.Mixer) {
		medium = append(medium, flagReport{"MIXER", "Interacts with a coin mixer", "medium"})
	}
	if raised(s.FakeToken) {
		medium = append(medium, flagReport{"FAKE TOKEN", "Associated with fake-token deployment", "medium"})
	}
	if positiveInt(s.NumberOfMaliciousContracts) {
		medium = append(medium, flagReport{
			fmt.Sprintf("MALICIOUS CONTRACTS (%s)", s.NumberOfMaliciousContracts),
			"Number of malicious contracts created by this address",
			"medium",
		})
	}
	if raised(s.DarkwebTransactions) {
		medium = append(medium, flagReport{"DARKWEB", "Darkweb transaction exposure", "medium"})
	}
	if raised(s.BlacklistDoubt) {
		medium = append(medium, flagReport{"BLACKLIST DOUBT", "Suspected blacklisted by authorities", "medium"})
	}

	if raised(s.FakeKYC) {
		info = append(info, flagReport{"FAKE KYC", "Suspected fake KYC/identity", "info"})
	}
	if raised(s.FakeStandardInterface) {
		info = append(info, flagReport{"FAKE STANDARD INTERFACE", "Contract mimics a standard interface (ERC20/721)", "info"})
	}
	if raised(s.GasAbuse) {
		info = append(info, flagReport{"GAS ABUSE", "Gas-abuse pattern detected", "info"})
	}

	return append(append(high, medium...), info...)
}

// overallRisk gives a one-word verdict from the raised flags.
func overallRisk(flags []flagReport) string {
	switch {
	case hasSeverity(flags, "high"):
		return "HIGH RISK"
	case hasSeverity(flags, "medium"):
		return "MEDIUM RISK"
	case len(flags) > 0:
		return "LOW RISK"
	default:
		return "CLEAN"
	}
}

func hasSeverity(flags []flagReport, sev string) bool {
	for _, f := range flags {
		if f.Severity == sev {
			return true
		}
	}
	return false
}
