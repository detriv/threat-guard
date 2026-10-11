package main

import (
	"testing"
)

func TestRaised(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1", true},
		{"0", false},
		{"", false},
		{" 1 ", true},
	}
	for _, c := range cases {
		if got := raised(c.in); got != c.want {
			t.Errorf("raised(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPositiveInt(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"0", false},
		{"1", true},
		{"3", true},
		{"", false},
		{"abc", false},
	}
	for _, c := range cases {
		if got := positiveInt(c.in); got != c.want {
			t.Errorf("positiveInt(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestChainID(t *testing.T) {
	if id, err := chainID("ethereum"); err != nil || id != 1 {
		t.Errorf("chainID(ethereum) = %d, %v; want 1", id, err)
	}
	if id, err := chainID("bsc"); err != nil || id != 56 {
		t.Errorf("chainID(bsc) = %d, %v; want 56", id, err)
	}
	if id, err := chainID("8453"); err != nil || id != 8453 {
		t.Errorf("chainID(8453) = %d, %v; want 8453", id, err)
	}
	if _, err := chainID("solana"); err == nil {
		t.Error("chainID(solana) should error")
	}
	if _, err := chainID(""); err == nil {
		t.Error("chainID(empty) should error")
	}
}

func TestIsAddress(t *testing.T) {
	good := "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
	if !isAddress(good) {
		t.Errorf("isAddress(%q) should be true", good)
	}
	bad := []string{"", "0x", "d8da6bf26964af9d7eed9e03e53415d37aa96045", "0x123", "0xZZZZ"}
	for _, b := range bad {
		if isAddress(b) {
			t.Errorf("isAddress(%q) should be false", b)
		}
	}
}

func TestSecurityFlagsClean(t *testing.T) {
	sec := &AddressSecurity{}
	if got := overallRisk(securityFlags(sec)); got != "CLEAN" {
		t.Errorf("clean verdict = %q, want CLEAN", got)
	}
}

func TestSecurityFlagsHigh(t *testing.T) {
	sec := &AddressSecurity{Sanctioned: "1"}
	flags := securityFlags(sec)
	if len(flags) == 0 {
		t.Fatal("expected flags for sanctioned address")
	}
	if got := overallRisk(flags); got != "HIGH RISK" {
		t.Errorf("verdict = %q, want HIGH RISK", got)
	}
	if flags[0].Severity != "high" {
		t.Errorf("first flag severity = %q, want high", flags[0].Severity)
	}
}

func TestSecurityFlagsMedium(t *testing.T) {
	sec := &AddressSecurity{Mixer: "1", MoneyLaundering: "1"}
	if got := overallRisk(securityFlags(sec)); got != "MEDIUM RISK" {
		t.Errorf("verdict = %q, want MEDIUM RISK", got)
	}
}

func TestSecurityFlagsMaliciousCount(t *testing.T) {
	sec := &AddressSecurity{NumberOfMaliciousContracts: "2"}
	flags := securityFlags(sec)
	if len(flags) != 1 {
		t.Fatalf("expected 1 flag, got %d", len(flags))
	}
	if !strings_Contains(flags[0].Label, "2") {
		t.Errorf("label %q should include the count", flags[0].Label)
	}
}

func strings_Contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
