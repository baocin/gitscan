package githttp

import (
	"strings"

	"github.com/skip2/go-qrcode"
)

// GenerateScaledQR generates a large, scannable QR code
// Uses 2 characters per module horizontally for better phone scanning
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
	// With 2 chars per module horizontally, that's 8 spaces on left/right
	quietMargin := "        " // 8 spaces (4 modules * 2 chars)
	qrWidth := len(bitmap[0])*2 + 16 // QR width + left/right quiet zones
	quietLine := strings.Repeat(" ", qrWidth)

	// Add top quiet zone (4 lines for 4 modules, since we render 2 rows per line)
	lines = append(lines, quietLine)
	lines = append(lines, quietLine)

	// Process 2 rows at a time using half-block characters
	// This gives us 2 vertical pixels per character line
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
			// Terminal: we want black modules to show as filled blocks
			var char string
			if top && bottom {
				char = "██" // Both black - full block, 2 wide
			} else if top && !bottom {
				char = "▀▀" // Top black, bottom white - upper half, 2 wide
			} else if !top && bottom {
				char = "▄▄" // Top white, bottom black - lower half, 2 wide
			} else {
				char = "  " // Both white - spaces, 2 wide
			}
			line.WriteString(char)
		}
		line.WriteString(quietMargin) // Right quiet zone
		lines = append(lines, line.String())
	}

	// Handle odd number of rows
	if len(bitmap)%2 == 1 {
		var line strings.Builder
		line.WriteString(quietMargin) // Left quiet zone
		y := len(bitmap) - 1
		for x := 0; x < len(bitmap[y]); x++ {
			if bitmap[y][x] {
				line.WriteString("▀▀")
			} else {
				line.WriteString("  ")
			}
		}
		line.WriteString(quietMargin) // Right quiet zone
		lines = append(lines, line.String())
	}

	// Add bottom quiet zone
	lines = append(lines, quietLine)
	lines = append(lines, quietLine)

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
