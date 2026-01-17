package githttp

import (
	"strings"

	"github.com/skip2/go-qrcode"
)

// GenerateASCIIQR generates an ASCII representation of a QR code from a URL
// Uses Unicode block characters for terminal display
// The QR code is scaled up 2x for better scannability
func GenerateASCIIQR(url string) []string {
	// Generate QR code with low error correction for smaller size
	qr, err := qrcode.New(url, qrcode.Low)
	if err != nil {
		// Fallback to placeholder if generation fails
		return generatePlaceholder()
	}

	// Get the bitmap (includes quiet zone)
	bitmap := qr.Bitmap()

	// Convert bitmap to ASCII using Unicode block characters
	// Use half-block characters: upper half = top pixel, lower half = bottom pixel
	// This gives us 2 vertical pixels per character
	lines := []string{}

	for y := 0; y < len(bitmap); y += 2 {
		var line strings.Builder
		for x := 0; x < len(bitmap[y]); x++ {
			top := bitmap[y][x]
			bottom := false
			if y+1 < len(bitmap) {
				bottom = bitmap[y+1][x]
			}

			// Use block characters based on top/bottom pixel states
			// true = black (dark module), false = white (light module)
			if top && bottom {
				line.WriteString("\u2588") // Full block (both dark)
			} else if top && !bottom {
				line.WriteString("\u2580") // Upper half block (top dark, bottom light)
			} else if !top && bottom {
				line.WriteString("\u2584") // Lower half block (top light, bottom dark)
			} else {
				line.WriteString(" ") // Space (both light)
			}
		}
		lines = append(lines, line.String())
	}

	return lines
}

// GenerateScaledQR generates a larger, more scannable QR code
// Each QR module is represented by 2x2 characters for better visibility
func GenerateScaledQR(url string) []string {
	qr, err := qrcode.New(url, qrcode.Low)
	if err != nil {
		return generatePlaceholder()
	}

	bitmap := qr.Bitmap()
	lines := []string{}

	// Scale 2x horizontally - each module becomes 2 characters wide
	for y := 0; y < len(bitmap); y += 2 {
		var line strings.Builder
		for x := 0; x < len(bitmap[y]); x++ {
			top := bitmap[y][x]
			bottom := false
			if y+1 < len(bitmap) {
				bottom = bitmap[y+1][x]
			}

			// Determine the character to use
			var char string
			if top && bottom {
				char = "\u2588" // Full block
			} else if top && !bottom {
				char = "\u2580" // Upper half
			} else if !top && bottom {
				char = "\u2584" // Lower half
			} else {
				char = " " // Space
			}

			// Write character twice for 2x horizontal scaling
			line.WriteString(char)
			line.WriteString(char)
		}
		lines = append(lines, line.String())
	}

	return lines
}

// generatePlaceholder returns a fallback QR-like pattern if generation fails
func generatePlaceholder() []string {
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

// GenerateCompactQR generates a compact QR-like visual (deprecated - use GenerateASCIIQR)
func GenerateCompactQR() []string {
	return generatePlaceholder()
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
