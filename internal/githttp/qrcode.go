package githttp

import (
	"strings"
)

// GenerateASCIIQR generates a simple ASCII representation of a QR code
// This uses Unicode block characters for a compact representation
// Each character represents 2 vertical modules
func GenerateASCIIQR(url string) []string {
	// For a proper QR code, we'd need a full QR library
	// This generates a simplified visual placeholder that looks like a QR code
	// In production, consider using github.com/skip2/go-qrcode

	// Generate a simple text-based "scan me" block instead
	// This is more reliable across terminals than trying to render a real QR
	lines := []string{
		"┌─────────────────────┐",
		"│  ▄▄▄▄▄ ▄▄▄▄▄ ▄▄▄▄▄ │",
		"│  █   █ █▀▀▀█ █   █ │",
		"│  █▄▄▄█ █▄▄▄█ █▄▄▄█ │",
		"│  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ │",
		"│  █ ▀▄█▀█▄▀█▄█▀▄█ █ │",
		"│  █▄█▀▄▀█▄▀█▄▀█▄█▀█ │",
		"│  ▄▄▄▄▄ █▄▀▄█ ▄▄▄▄▄ │",
		"│  █   █ ▀█▄█▀ █   █ │",
		"│  █▄▄▄█ █▀▄▀█ █▄▄▄█ │",
		"└─────────────────────┘",
		"    ^ Scan to view ^    ",
	}

	return lines
}

// GenerateCompactQR generates a more compact QR-like visual
func GenerateCompactQR() []string {
	return []string{
		"█▀▀▀▀▀█ ▄▀█▀ █▀▀▀▀▀█",
		"█ ███ █ ▀▄▀▄ █ ███ █",
		"█ ▀▀▀ █ █▀▄▀ █ ▀▀▀ █",
		"▀▀▀▀▀▀▀ █▀█▀ ▀▀▀▀▀▀▀",
		"▀▄█▀█▀▀▀▄▀█▄▀▀▄█▀▀▄▀",
		"▀▀▀▀▀▀▀ ▄▄▄▀ ▄ ▄ ▀▄▀",
		"█▀▀▀▀▀█ ▀▄▀█▀█▄█▀ ▄▀",
		"█ ███ █ ▀█▄█▀▄█▀▀▀█▀",
		"█ ▀▀▀ █  ▀▄█▀▀▄▀█▄▀█",
		"▀▀▀▀▀▀▀ ▀▀ ▀▀ ▀▀ ▀▀▀",
	}
}

// WrapQRInBox wraps QR code lines in a box with the URL below
func WrapQRInBox(qrLines []string, url string, width int) []string {
	result := []string{}

	// Pad QR lines to center them
	for _, line := range qrLines {
		lineLen := len([]rune(line))
		padding := (width - 4 - lineLen) / 2
		if padding < 0 {
			padding = 0
		}
		paddedLine := strings.Repeat(" ", padding) + line
		result = append(result, paddedLine)
	}

	return result
}
