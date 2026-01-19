package githttp

import (
	"strings"

	"github.com/skip2/go-qrcode"
)

// GenerateScaledQR generates a compact, scannable QR code using half-blocks (Dense1x2 style)
// Uses Unicode half-blocks (▀▄█) to encode 2 vertical pixels per character for 75% size reduction
func GenerateScaledQR(url string) []string {
	qr, err := qrcode.New(url, qrcode.Medium)
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
	quietMargin := strings.Repeat(" ", 4) // 4 modules (1 char per module)
	qrWidth := len(bitmap[0]) + 8          // QR width + left/right quiet zones (4 each side)
	quietLine := strings.Repeat(" ", qrWidth)

	// Add top quiet zone (2 lines for 4 modules, since we encode 2 rows per line)
	lines = append(lines, quietLine)
	lines = append(lines, quietLine)

	// Process 2 rows at a time using half-block characters (Dense1x2 approach)
	// This gives us 2 vertical pixels per character, making QR codes 50% shorter
	for y := 0; y < len(bitmap); y += 2 {
		var line strings.Builder
		line.WriteString(quietMargin) // Left quiet zone

		for x := 0; x < len(bitmap[y]); x++ {
			top := bitmap[y][x]
			bottom := false
			if y+1 < len(bitmap) {
				bottom = bitmap[y+1][x]
			}

			// QR codes: true = black module (data), false = white (background)
			// Use Unicode half-blocks to encode 2 pixels vertically
			if top && bottom {
				line.WriteString("█") // Both black - full block
			} else if top && !bottom {
				line.WriteString("▀") // Top black, bottom white - upper half
			} else if !top && bottom {
				line.WriteString("▄") // Top white, bottom black - lower half
			} else {
				line.WriteString(" ") // Both white - space
			}
		}
		line.WriteString(quietMargin) // Right quiet zone
		lines = append(lines, line.String())
	}

	// Handle odd number of rows
	if len(bitmap)%2 == 1 {
		var line strings.Builder
		line.WriteString(quietMargin)
		y := len(bitmap) - 1
		for x := 0; x < len(bitmap[y]); x++ {
			if bitmap[y][x] {
				line.WriteString("▀") // Top row only, use upper half block
			} else {
				line.WriteString(" ")
			}
		}
		line.WriteString(quietMargin)
		lines = append(lines, line.String())
	}

	// Add bottom quiet zone (2 lines for 4 modules)
	lines = append(lines, quietLine)
	lines = append(lines, quietLine)

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
