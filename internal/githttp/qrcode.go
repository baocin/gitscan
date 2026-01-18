package githttp

import (
	"strings"

	"github.com/skip2/go-qrcode"
)

// GenerateScaledQR generates a large, scannable QR code
// Uses 2 characters per module with full blocks for maximum reliability and 80-char compatibility
func GenerateScaledQR(url string) []string {
	qr, err := qrcode.New(url, qrcode.High)
	if err != nil {
		// Return error message instead of fake QR
		return []string{
			"[QR generation failed: " + err.Error() + "]",
			"Visit: " + url,
		}
	}

	// Disable the built-in border, we'll handle quiet zones ourselves
	qr.DisableBorder = true
	bitmap := qr.Bitmap()

	if len(bitmap) == 0 {
		return []string{"[QR bitmap empty]", "Visit: " + url}
	}

	lines := []string{}

	// Quiet zone: 4 modules of white space on all sides (QR spec recommends 4)
	// With 2 chars per module horizontally, that's 8 spaces on left/right
	quietMargin := strings.Repeat(" ", 8) // 4 modules * 2 chars
	qrWidth := len(bitmap[0])*2 + 16 // QR width + left/right quiet zones
	quietLine := strings.Repeat(" ", qrWidth)

	// Add top quiet zone (4 lines for 4 modules vertically)
	for i := 0; i < 4; i++ {
		lines = append(lines, quietLine)
	}

	// Process 1 row at a time, 2 chars per module
	// Use only full blocks and spaces for maximum terminal compatibility
	for y := 0; y < len(bitmap); y++ {
		var line strings.Builder
		line.WriteString(quietMargin) // Left quiet zone

		for x := 0; x < len(bitmap[y]); x++ {
			// QR codes: true = black module (data), false = white (background)
			if bitmap[y][x] {
				line.WriteString("██") // Black module - 2 full blocks
			} else {
				line.WriteString("  ") // White module - 2 spaces
			}
		}
		line.WriteString(quietMargin) // Right quiet zone
		lines = append(lines, line.String())
	}

	// Add bottom quiet zone (4 lines)
	for i := 0; i < 4; i++ {
		lines = append(lines, quietLine)
	}

	return lines
}

// GenerateASCIIQR generates a standard size QR code (smaller than scaled)
func GenerateASCIIQR(url string) []string {
	qr, err := qrcode.New(url, qrcode.Low)
	if err != nil {
		return []string{"[QR error: " + err.Error() + "]"}
	}

	qr.DisableBorder = true
	bitmap := qr.Bitmap()
	lines := []string{}

	for y := 0; y < len(bitmap); y += 2 {
		var line strings.Builder
		for x := 0; x < len(bitmap[y]); x++ {
			top := bitmap[y][x]
			bottom := false
			if y+1 < len(bitmap) {
				bottom = bitmap[y+1][x]
			}

			if top && bottom {
				line.WriteString("█")
			} else if top && !bottom {
				line.WriteString("▀")
			} else if !top && bottom {
				line.WriteString("▄")
			} else {
				line.WriteString(" ")
			}
		}
		lines = append(lines, line.String())
	}

	return lines
}

// WrapQRInBox wraps QR code lines in a box with the URL below
func WrapQRInBox(qrLines []string, url string, width int) []string {
	result := []string{}

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
