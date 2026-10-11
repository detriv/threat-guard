package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/TeneoProtocolAI/teneo-agent-sdk/pkg/agent"
	"github.com/joho/godotenv"
)

// ---------------------------------------------------------------------------
// Threat Guard — EVM address / domain / phishing security screening agent.
//
// Commands:
//   help
//   wallet <chain> <address>   - address risk screening
//   site   <domain-or-url>     - phishing site check
//   flags  <chain> <address>   - full flag breakdown (structured)
//
// Data source: GoPlus Labs Security API (free tier, no key required).
// ---------------------------------------------------------------------------

type ThreatGuardAgent struct{}

func NewThreatGuardAgent() *ThreatGuardAgent { return &ThreatGuardAgent{} }

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

const helpText = `Threat Guard — EVM address, domain and phishing security screening

Commands:
  help
      Show this message. Free.

  wallet <chain> <address>
      Screen an EVM wallet or contract address for scam exposure:
      cybercrime, money laundering, mixer use, malicious contracts created,
      phishing activity, sanctions and fake KYC. Returns a plain-text risk
      report with a HIGH / MEDIUM / LOW / CLEAN verdict.
      Example: wallet ethereum 0xd8da6bf26964af9d7eed9e03e53415d37aa96045
      Price: $0.005 per query

  site <domain-or-url>
      Check whether a domain or URL is a known phishing site.
      Example: site uniswap.org
      Price: $0.003 per query

  flags <chain> <address>
      Full risk-flag breakdown for an address as structured data: every
      GoPlus security flag with its raw value, not just the positives.
      Example: flags base 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913
      Price: $0.01 per query

Supported chains: ethereum, bsc, base, polygon, avalanche
Data source: GoPlus Labs Security API (free tier)
Pricing is in USDC on the Teneo network.`

// ---------------------------------------------------------------------------
// Task entry point
// ---------------------------------------------------------------------------

func (a *ThreatGuardAgent) ProcessTask(ctx context.Context, task string) (string, error) {
	task = strings.TrimSpace(task)
	task = strings.TrimPrefix(task, "/")
	if task == "" {
		return "No command provided. Type 'help' to see what I can do.", nil
	}

	fields := strings.Fields(task)
	command := strings.ToLower(fields[0])
	args := fields[1:]

	switch command {
	case "help", "commands", "capabilities", "what can you do":
		return helpText, nil

	case "wallet", "check", "address":
		return a.handleWallet(args)

	case "site", "phishing", "domain", "url":
		return a.handleSite(args)

	case "flags", "detail", "breakdown":
		return a.handleFlags(args)

	default:
		return fmt.Sprintf(
			"Unknown command '%s'.\n\nAvailable: help, wallet, site, flags\nType 'help' for details and examples.",
			command,
		), nil
	}
}

// ---------------------------------------------------------------------------
// wallet — address risk screening
// ---------------------------------------------------------------------------

func (a *ThreatGuardAgent) handleWallet(args []string) (string, error) {
	if len(args) < 2 {
		return "Usage: wallet <chain> <address>\nExample: wallet ethereum 0xd8da6bf26964af9d7eed9e03e53415d37aa96045", nil
	}
	id, err := chainID(args[0])
	if err != nil {
		return err.Error(), nil
	}
	addr := args[1]
	if !isAddress(addr) {
		return fmt.Sprintf("'%s' does not look like an EVM address (expected 0x + 40 hex chars).", addr), nil
	}

	sec, err := fetchAddressSecurity(id, addr)
	if err != nil {
		return fmt.Sprintf("Could not screen address: %v", err), nil
	}

	flags := securityFlags(sec)
	verdict := overallRisk(flags)

	var b strings.Builder
	fmt.Fprintf(&b, "Threat Guard — wallet screening\n")
	fmt.Fprintf(&b, "Address: %s\n", strings.ToLower(addr))
	fmt.Fprintf(&b, "Chain ID: %d\n", id)
	fmt.Fprintf(&b, "Verdict: %s\n\n", verdict)

	if len(flags) == 0 {
		b.WriteString("No security flags raised for this address on this chain.\n")
	} else {
		fmt.Fprintf(&b, "Flags raised (%d):\n", len(flags))
		for _, f := range flags {
			fmt.Fprintf(&b, "  [%s] %s — %s\n", strings.ToUpper(f.Severity), f.Label, f.Detail)
		}
	}

	kind := "wallet"
	if raised(sec.ContractAddress) {
		kind = "contract"
	}
	if sec.DataSource != "" {
		fmt.Fprintf(&b, "\nData source: %s", sec.DataSource)
	}
	fmt.Fprintf(&b, "\nAddress type: %s", kind)
	fmt.Fprintf(&b, "\nVerdict note: %s", verdictNote(verdict))
	return b.String(), nil
}

func verdictNote(v string) string {
	switch v {
	case "HIGH RISK":
		return "Do not interact with this address."
	case "MEDIUM RISK":
		return "Proceed with caution; verify the counterparty independently."
	case "LOW RISK":
		return "Only informational flags raised."
	default:
		return "No flags found in the GoPlus database for this chain."
	}
}

// ---------------------------------------------------------------------------
// site — phishing domain check
// ---------------------------------------------------------------------------

func (a *ThreatGuardAgent) handleSite(args []string) (string, error) {
	if len(args) < 1 {
		return "Usage: site <domain-or-url>\nExample: site uniswap.org", nil
	}
	target := strings.TrimSpace(strings.Join(args, " "))

	site, err := fetchPhishingSite(target)
	if err != nil {
		return fmt.Sprintf("Could not check target: %v", err), nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Threat Guard — phishing check\n")
	fmt.Fprintf(&b, "Target: %s\n", target)
	if site.PhishingSite == 1 {
		b.WriteString("Verdict: KNOWN PHISHING SITE — do not visit or connect a wallet.\n")
	} else {
		b.WriteString("Verdict: NOT flagged as phishing by GoPlus.\n")
	}

	if len(site.WebsiteContractSecurity) > 0 {
		fmt.Fprintf(&b, "\nRelated contracts flagged (%d):\n", len(site.WebsiteContractSecurity))
		for _, c := range site.WebsiteContractSecurity {
			fmt.Fprintf(&b, "  %s\n", c)
		}
	} else {
		b.WriteString("\nNo related flagged contracts reported.\n")
	}

	b.WriteString("\nNote: this checks GoPlus's phishing database only. A clean result is not proof a site is legitimate.")
	return b.String(), nil
}

// ---------------------------------------------------------------------------
// flags — full structured breakdown
// ---------------------------------------------------------------------------

func (a *ThreatGuardAgent) handleFlags(args []string) (string, error) {
	if len(args) < 2 {
		return "Usage: flags <chain> <address>\nExample: flags base 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", nil
	}
	id, err := chainID(args[0])
	if err != nil {
		return err.Error(), nil
	}
	addr := args[1]
	if !isAddress(addr) {
		return fmt.Sprintf("'%s' does not look like an EVM address (expected 0x + 40 hex chars).", addr), nil
	}

	sec, err := fetchAddressSecurity(id, addr)
	if err != nil {
		return fmt.Sprintf("Could not fetch flags: %v", err), nil
	}

	flags := securityFlags(sec)

	// Emit every raw flag sorted alphabetically as JSON so the caller sees
	// the full picture, not just the raised ones.
	raw := rawFlags(sec)
	payload := map[string]interface{}{
		"address":     strings.ToLower(addr),
		"chain_id":    id,
		"verdict":     overallRisk(flags),
		"raised":      len(flags),
		"raised_list": flags,
		"all_flags":   raw,
		"is_contract": raised(sec.ContractAddress),
		"source":      "GoPlus Labs Security API",
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}

	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Sprintf("Could not format output: %v", err), nil
	}
	return string(out), nil
}

// rawFlags returns every GoPlus field as a flat key/value map.
func rawFlags(s *AddressSecurity) map[string]string {
	return map[string]string{
		"cybercrime":                    s.Cybercrime,
		"money_laundering":              s.MoneyLaundering,
		"number_of_malicious_contracts": s.NumberOfMaliciousContracts,
		"gas_abuse":                     s.GasAbuse,
		"financial_crime":               s.FinancialCrime,
		"darkweb_transactions":          s.DarkwebTransactions,
		"reinit":                        s.Reinit,
		"phishing_activities":           s.PhishingActivities,
		"contract_address":              s.ContractAddress,
		"fake_kyc":                      s.FakeKYC,
		"blacklist_doubt":               s.BlacklistDoubt,
		"fake_standard_interface":       s.FakeStandardInterface,
		"data_source":                   s.DataSource,
		"stealing_attack":               s.StealingAttack,
		"blackmail_activities":          s.BlackmailActivities,
		"sanctioned":                    s.Sanctioned,
		"malicious_mining_activities":   s.MaliciousMiningActivities,
		"mixer":                         s.Mixer,
		"fake_token":                    s.FakeToken,
		"honeypot_related_address":      s.HoneypotRelatedAddress,
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env not found, using environment variables")
	}

	config := agent.DefaultConfig()
	config.Name = "Threat Guard"
	config.Description = "EVM address, domain and phishing security screening via the GoPlus Labs Security API."
	config.Version = "1.0.0"
	config.Capabilities = []string{
		"address_risk_screening",
		"phishing_domain_detection",
		"malicious_contract_attribution",
		"sanctions_compliance_check",
		"threat_intel_help",
	}
	config.PrivateKey = os.Getenv("PRIVATE_KEY")

	if config.PrivateKey == "" {
		log.Fatal("PRIVATE_KEY environment variable is required")
	}

	if port := os.Getenv("HEALTH_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			config.HealthPort = p
		}
	}

	var mintNewNFT bool
	var existingTokenID uint64
	if tokenIDStr := os.Getenv("NFT_TOKEN_ID"); tokenIDStr != "" {
		id, err := strconv.ParseUint(tokenIDStr, 10, 64)
		if err != nil {
			log.Fatalf("Invalid NFT_TOKEN_ID: %s", tokenIDStr)
		}
		existingTokenID = id
	} else {
		mintNewNFT = true
		log.Println("NFT_TOKEN_ID not set, will mint a new NFT for this agent")
	}

	enhanced, err := agent.NewEnhancedAgent(&agent.EnhancedAgentConfig{
		Config:       config,
		AgentHandler: NewThreatGuardAgent(),
		Mint:         mintNewNFT,
		TokenID:      existingTokenID,
	})
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	log.Printf("Threat Guard starting (health port %d)", config.HealthPort)
	if err := enhanced.Run(); err != nil {
		log.Fatalf("Agent failed: %v", err)
	}
}
