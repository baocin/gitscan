package blocklist

import (
	"time"
)

// SourceType identifies the type of blocklist source
type SourceType string

const (
	SourceTypeSpamhausDROP       SourceType = "spamhaus-drop"
	SourceTypeFeodoTracker       SourceType = "feodo-tracker"
	SourceTypeEmergingThreats    SourceType = "emerging-threats"
	SourceTypeCIArmy             SourceType = "ci-army"
)

// Source represents a threat intelligence feed source
type Source struct {
	Type        SourceType
	Name        string
	URL         string
	Format      Format
	Description string
	UpdateInterval time.Duration
	Enabled     bool
}

// Format describes how to parse the blocklist data
type Format string

const (
	FormatCIDR      Format = "cidr"       // CIDR notation with optional comments
	FormatPlainIP   Format = "plain_ip"   // One IP per line
	FormatCSV       Format = "csv"        // CSV with IP in first column
	FormatSpamhaus  Format = "spamhaus"   // Spamhaus-specific format
)

// DefaultSources returns the default set of threat intelligence sources
func DefaultSources() []Source {
	return []Source{
		{
			Type:           SourceTypeSpamhausDROP,
			Name:           "Spamhaus DROP",
			URL:            "https://www.spamhaus.org/drop/drop.txt",
			Format:         FormatSpamhaus,
			Description:    "Spamhaus Don't Route Or Peer - known hostile networks (~1,400 CIDRs)",
			UpdateInterval: 24 * time.Hour,
			Enabled:        true,
		},
		{
			Type:           SourceTypeFeodoTracker,
			Name:           "Feodo Tracker",
			URL:            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
			Format:         FormatPlainIP,
			Description:    "abuse.ch Feodo Tracker - botnet C&C server IPs",
			UpdateInterval: 6 * time.Hour,
			Enabled:        true,
		},
		{
			Type:           SourceTypeEmergingThreats,
			Name:           "Emerging Threats Compromised IPs",
			URL:            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
			Format:         FormatPlainIP,
			Description:    "Emerging Threats - known compromised hosts (~5,000 IPs)",
			UpdateInterval: 12 * time.Hour,
			Enabled:        true,
		},
		{
			Type:           SourceTypeCIArmy,
			Name:           "CI Army Bad Guys",
			URL:            "https://cinsscore.com/list/ci-badguys.txt",
			Format:         FormatPlainIP,
			Description:    "Collective Intelligence - malicious IPs (~15,000 IPs)",
			UpdateInterval: 12 * time.Hour,
			Enabled:        true,
		},
	}
}

// GetSource returns a source by type
func GetSource(sources []Source, sourceType SourceType) *Source {
	for i := range sources {
		if sources[i].Type == sourceType {
			return &sources[i]
		}
	}
	return nil
}

// EnabledSources returns only enabled sources
func EnabledSources(sources []Source) []Source {
	var enabled []Source
	for _, s := range sources {
		if s.Enabled {
			enabled = append(enabled, s)
		}
	}
	return enabled
}
