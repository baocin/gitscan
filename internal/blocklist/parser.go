package blocklist

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

// Entry represents a parsed blocklist entry
type Entry struct {
	IP     string // IP address or CIDR
	CIDR   *net.IPNet
	Reason string
	Source SourceType
}

// ParseBlocklist parses blocklist data according to the specified format
func ParseBlocklist(data string, format Format, source SourceType) ([]Entry, error) {
	switch format {
	case FormatSpamhaus:
		return parseSpamhaus(data, source)
	case FormatPlainIP:
		return parsePlainIP(data, source)
	case FormatCIDR:
		return parseCIDR(data, source)
	case FormatCSV:
		return parseCSV(data, source)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// parseSpamhaus parses Spamhaus DROP/EDROP format
// Format: CIDR ; SBL123 ; Description
// Example: 1.2.3.0/24 ; SBL456789 ; Spamhaus BCL
func parseSpamhaus(data string, source SourceType) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(strings.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Parse format: CIDR ; SBL ; Reason
		parts := strings.Split(line, ";")
		if len(parts) < 1 {
			continue
		}

		cidrStr := strings.TrimSpace(parts[0])
		reason := "Spamhaus blocklist"
		if len(parts) >= 3 {
			reason = strings.TrimSpace(parts[2])
		}

		// Parse CIDR
		_, ipnet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			// Try as single IP
			ip := net.ParseIP(cidrStr)
			if ip == nil {
				continue // Skip invalid entries
			}
			// Convert single IP to /32 or /128 CIDR
			if ip.To4() != nil {
				cidrStr = cidrStr + "/32"
			} else {
				cidrStr = cidrStr + "/128"
			}
			_, ipnet, err = net.ParseCIDR(cidrStr)
			if err != nil {
				continue
			}
		}

		entries = append(entries, Entry{
			IP:     cidrStr,
			CIDR:   ipnet,
			Reason: reason,
			Source: source,
		})
	}

	return entries, scanner.Err()
}

// parsePlainIP parses plain IP lists (one IP per line)
func parsePlainIP(data string, source SourceType) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(strings.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Parse IP
		ip := net.ParseIP(line)
		if ip == nil {
			continue // Skip invalid IPs
		}

		// Convert to CIDR
		cidrStr := line
		if ip.To4() != nil {
			cidrStr = line + "/32"
		} else {
			cidrStr = line + "/128"
		}

		_, ipnet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}

		entries = append(entries, Entry{
			IP:     cidrStr,
			CIDR:   ipnet,
			Reason: fmt.Sprintf("Blocklisted by %s", source),
			Source: source,
		})
	}

	return entries, scanner.Err()
}

// parseCIDR parses CIDR lists (one CIDR per line, optional comments)
func parseCIDR(data string, source SourceType) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(strings.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Extract CIDR (before any comment)
		cidrStr := line
		if idx := strings.Index(line, "#"); idx >= 0 {
			cidrStr = strings.TrimSpace(line[:idx])
		}

		// Parse CIDR
		_, ipnet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue // Skip invalid entries
		}

		entries = append(entries, Entry{
			IP:     cidrStr,
			CIDR:   ipnet,
			Reason: fmt.Sprintf("Blocklisted by %s", source),
			Source: source,
		})
	}

	return entries, scanner.Err()
}

// parseCSV parses CSV format (assumes IP is in first column)
func parseCSV(data string, source SourceType) ([]Entry, error) {
	var entries []Entry
	scanner := bufio.NewScanner(strings.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse CSV (simple split on comma)
		parts := strings.Split(line, ",")
		if len(parts) < 1 {
			continue
		}

		ipStr := strings.TrimSpace(parts[0])

		// Try parsing as IP first
		ip := net.ParseIP(ipStr)
		if ip != nil {
			// Convert to CIDR
			cidrStr := ipStr
			if ip.To4() != nil {
				cidrStr = ipStr + "/32"
			} else {
				cidrStr = ipStr + "/128"
			}

			_, ipnet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				continue
			}

			entries = append(entries, Entry{
				IP:     cidrStr,
				CIDR:   ipnet,
				Reason: fmt.Sprintf("Blocklisted by %s", source),
				Source: source,
			})
			continue
		}

		// Try parsing as CIDR
		_, ipnet, err := net.ParseCIDR(ipStr)
		if err != nil {
			continue // Skip invalid entries
		}

		entries = append(entries, Entry{
			IP:     ipStr,
			CIDR:   ipnet,
			Reason: fmt.Sprintf("Blocklisted by %s", source),
			Source: source,
		})
	}

	return entries, scanner.Err()
}

// ContainsIP checks if an IP address is contained in a CIDR block
func ContainsIP(cidr *net.IPNet, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return cidr.Contains(ip)
}
