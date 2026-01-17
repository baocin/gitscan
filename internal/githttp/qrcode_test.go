package githttp

import (
	"strings"
	"testing"
)

func TestGenerateScaledQR(t *testing.T) {
	// Test with a typical report URL
	url := "https://git.vet/r/abc12345"
	lines := GenerateScaledQR(url)

	if len(lines) == 0 {
		t.Fatal("GenerateScaledQR returned empty result")
	}

	// Check for error messages
	if strings.Contains(lines[0], "[QR") {
		t.Fatalf("QR generation failed: %s", lines[0])
	}

	// All lines should have the same width (consistent quiet zones)
	firstWidth := len([]rune(lines[0]))
	for i, line := range lines {
		lineWidth := len([]rune(line))
		if lineWidth != firstWidth {
			t.Errorf("Line %d has width %d, expected %d (first line width)", i, lineWidth, firstWidth)
		}
	}

	t.Logf("QR code has %d lines, width %d chars", len(lines), firstWidth)
}

func TestGenerateScaledQRFitsInBox(t *testing.T) {
	// The report box is 80 characters wide
	// Inner content area is 80 - 4 = 76 characters (box borders + spaces)
	boxInnerWidth := 76

	// Test various URL lengths
	testURLs := []string{
		"https://git.vet/r/a",         // Very short
		"https://git.vet/r/abc12345",  // Typical 8-char commit
		"https://git.vet/r/abc123456789ab", // 12-char commit
	}

	for _, url := range testURLs {
		lines := GenerateScaledQR(url)
		if len(lines) == 0 {
			t.Errorf("Empty QR for URL: %s", url)
			continue
		}

		// Check if QR fits in box
		maxWidth := 0
		for _, line := range lines {
			width := len([]rune(line))
			if width > maxWidth {
				maxWidth = width
			}
		}

		if maxWidth > boxInnerWidth {
			t.Errorf("QR code for %s is %d chars wide, exceeds box inner width of %d",
				url, maxWidth, boxInnerWidth)
		} else {
			t.Logf("QR for %s: %d chars wide (fits in %d)", url, maxWidth, boxInnerWidth)
		}
	}
}

func TestGenerateScaledQRHasQuietZones(t *testing.T) {
	url := "https://git.vet/r/test1234"
	lines := GenerateScaledQR(url)

	if len(lines) < 4 {
		t.Fatal("QR code too short to have proper quiet zones")
	}

	// Top quiet zone should be all spaces
	for i := 0; i < 2; i++ {
		if strings.TrimSpace(lines[i]) != "" {
			t.Errorf("Top quiet zone line %d should be all spaces, got: %q", i, lines[i])
		}
	}

	// Bottom quiet zone should be all spaces
	for i := len(lines) - 2; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "" {
			t.Errorf("Bottom quiet zone line %d should be all spaces, got: %q", i, lines[i])
		}
	}

	// Middle lines (QR data) should have left/right quiet zones (spaces at start and end)
	for i := 2; i < len(lines)-2; i++ {
		line := lines[i]
		// Check for left quiet zone (at least 8 spaces for 4 modules * 2 chars)
		if !strings.HasPrefix(line, "        ") {
			t.Errorf("Line %d missing left quiet zone: %q", i, line[:min(20, len(line))])
		}
		// Check for right quiet zone
		if !strings.HasSuffix(line, "        ") {
			t.Errorf("Line %d missing right quiet zone: %q", i, line[max(0, len(line)-20):])
		}
	}
}

func TestGenerateScaledQRUsesCorrectCharacters(t *testing.T) {
	url := "https://git.vet/r/test"
	lines := GenerateScaledQR(url)

	validChars := map[rune]bool{
		' ':  true, // White/empty
		'█':  true, // Full block
		'▀':  true, // Upper half block
		'▄':  true, // Lower half block
	}

	for i, line := range lines {
		for j, r := range line {
			if !validChars[r] {
				t.Errorf("Invalid character at line %d, pos %d: %q (U+%04X)", i, j, string(r), r)
			}
		}
	}
}

func TestGenerateASCIIQR(t *testing.T) {
	url := "https://git.vet/r/test"
	lines := GenerateASCIIQR(url)

	if len(lines) == 0 {
		t.Fatal("GenerateASCIIQR returned empty result")
	}

	// Should be smaller than scaled version (1 char per module instead of 2)
	scaledLines := GenerateScaledQR(url)

	// Compare widths (accounting for quiet zones in scaled version)
	scaledWidth := len([]rune(scaledLines[2])) // Skip quiet zone lines
	asciiWidth := len([]rune(lines[0]))

	// ASCII version should be roughly half the width of scaled (minus quiet zones)
	// Scaled uses 2 chars per module + 16 chars quiet zone
	// ASCII uses 1 char per module, no quiet zone
	if asciiWidth >= scaledWidth {
		t.Errorf("ASCII QR (%d) should be narrower than scaled QR (%d)", asciiWidth, scaledWidth)
	}
}

func TestGenerateScaledQRErrorHandling(t *testing.T) {
	// Test with invalid URL (too long for QR code)
	longURL := "https://git.vet/r/" + strings.Repeat("a", 3000)
	lines := GenerateScaledQR(longURL)

	if len(lines) == 0 {
		t.Fatal("Should return error message, not empty result")
	}

	// Should contain error indicator
	if !strings.Contains(lines[0], "[QR") && !strings.Contains(lines[0], "Visit:") {
		t.Errorf("Expected error message or fallback, got: %s", lines[0])
	}
}

func TestQRCodeModuleConsistency(t *testing.T) {
	// Verify that each QR module is represented by exactly 2 characters
	url := "https://git.vet/r/x"
	lines := GenerateScaledQR(url)

	// Find a line with actual QR data (not quiet zone)
	var dataLine string
	for i := 2; i < len(lines)-2; i++ {
		if strings.TrimSpace(lines[i]) != "" {
			dataLine = lines[i]
			break
		}
	}

	if dataLine == "" {
		t.Fatal("Could not find QR data line")
	}

	// Check that the line length is even (2 chars per module)
	if len([]rune(dataLine))%2 != 0 {
		t.Errorf("QR line has odd width %d, expected even (2 chars per module)", len([]rune(dataLine)))
	}

	// Check character pairs
	runes := []rune(dataLine)
	for i := 0; i < len(runes); i += 2 {
		if i+1 >= len(runes) {
			break
		}
		// Each pair should be identical (same block type repeated twice)
		if runes[i] != runes[i+1] {
			t.Errorf("Position %d-%d: chars %q and %q should match", i, i+1, string(runes[i]), string(runes[i+1]))
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
