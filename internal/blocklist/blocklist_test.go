package blocklist

import (
	"strings"
	"testing"
)

func TestParseSpamhaus(t *testing.T) {
	data := `; Spamhaus DROP List
; Last updated: Mon Jan 20 00:00:00 2025 GMT
1.2.3.0/24 ; SBL123456 ; Spamhaus BCL
10.0.0.0/8 ; SBL789012 ; Reserved space
192.168.1.0/24 ; SBL345678 ; Test network`

	entries, err := parseSpamhaus(data, SourceTypeSpamhausDROP)
	if err != nil {
		t.Fatalf("parseSpamhaus failed: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Verify first entry
	if entries[0].IP != "1.2.3.0/24" {
		t.Errorf("expected IP 1.2.3.0/24, got %s", entries[0].IP)
	}
	if entries[0].Reason != "Spamhaus BCL" {
		t.Errorf("expected reason 'Spamhaus BCL', got %s", entries[0].Reason)
	}
}

func TestParsePlainIP(t *testing.T) {
	data := `# Blocklist
# One IP per line
1.2.3.4
5.6.7.8
# Comment
9.10.11.12`

	entries, err := parsePlainIP(data, SourceTypeFeodoTracker)
	if err != nil {
		t.Fatalf("parsePlainIP failed: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Verify IPs are converted to CIDR
	if entries[0].IP != "1.2.3.4/32" {
		t.Errorf("expected IP 1.2.3.4/32, got %s", entries[0].IP)
	}
}

func TestParseCIDR(t *testing.T) {
	data := `1.2.3.0/24 # Test network
10.0.0.0/8
192.168.0.0/16 # Private`

	entries, err := parseCIDR(data, SourceTypeSpamhausDROP)
	if err != nil {
		t.Fatalf("parseCIDR failed: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	if entries[0].IP != "1.2.3.0/24" {
		t.Errorf("expected IP 1.2.3.0/24, got %s", entries[0].IP)
	}
}

func TestContainsIP(t *testing.T) {
	data := "10.0.0.0/8"
	entries, err := parseCIDR(data, SourceTypeSpamhausDROP)
	if err != nil {
		t.Fatalf("parseCIDR failed: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"11.0.0.1", false},
		{"192.168.1.1", false},
	}

	for _, tt := range tests {
		result := ContainsIP(entries[0].CIDR, tt.ip)
		if result != tt.expected {
			t.Errorf("ContainsIP(%s) = %v, expected %v", tt.ip, result, tt.expected)
		}
	}
}

func TestDefaultSources(t *testing.T) {
	sources := DefaultSources()

	if len(sources) < 3 {
		t.Errorf("expected at least 3 default sources, got %d", len(sources))
	}

	// Verify Spamhaus DROP is present
	found := false
	for _, s := range sources {
		if s.Type == SourceTypeSpamhausDROP {
			found = true
			if !strings.Contains(s.URL, "spamhaus.org") {
				t.Errorf("Spamhaus DROP URL should contain 'spamhaus.org', got %s", s.URL)
			}
		}
	}

	if !found {
		t.Error("Spamhaus DROP source not found in defaults")
	}
}

func TestEnabledSources(t *testing.T) {
	sources := []Source{
		{Type: SourceTypeSpamhausDROP, Enabled: true},
		{Type: SourceTypeFeodoTracker, Enabled: false},
		{Type: SourceTypeEmergingThreats, Enabled: true},
	}

	enabled := EnabledSources(sources)

	if len(enabled) != 2 {
		t.Errorf("expected 2 enabled sources, got %d", len(enabled))
	}

	for _, s := range enabled {
		if !s.Enabled {
			t.Errorf("EnabledSources returned disabled source: %s", s.Type)
		}
	}
}
