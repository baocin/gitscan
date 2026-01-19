package githttp

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

// Sideband channels as defined by git protocol
const (
	SidebandData     byte = 1 // Pack data
	SidebandProgress byte = 2 // Progress messages (remote: ...)
	SidebandError    byte = 3 // Error messages
)

// ANSI color codes
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
)

// SidebandWriter writes git protocol sideband messages
type SidebandWriter struct {
	w         io.Writer
	mu        sync.Mutex
	useColors bool
}

// NewSidebandWriter creates a new sideband writer
func NewSidebandWriter(w io.Writer, useColors bool) *SidebandWriter {
	return &SidebandWriter{
		w:         w,
		useColors: useColors,
	}
}

// WriteProgress writes a progress message (displayed as "remote: ...")
func (s *SidebandWriter) WriteProgress(msg string) error {
	return s.writeBand(SidebandProgress, msg+"\n")
}

// WriteProgressf writes a formatted progress message
func (s *SidebandWriter) WriteProgressf(format string, args ...interface{}) error {
	return s.WriteProgress(fmt.Sprintf(format, args...))
}

// WriteError writes an error message
func (s *SidebandWriter) WriteError(msg string) error {
	return s.writeBand(SidebandError, msg+"\n")
}

// WriteErrorf writes a formatted error message
func (s *SidebandWriter) WriteErrorf(format string, args ...interface{}) error {
	return s.WriteError(fmt.Sprintf(format, args...))
}

// WriteEmptyLine writes an empty progress line
func (s *SidebandWriter) WriteEmptyLine() error {
	return s.WriteProgress("")
}

// writeBand writes a message to the specified sideband channel
func (s *SidebandWriter) writeBand(band byte, data string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// pkt-line format: 4 hex digits length + band byte + data
	// length includes the 4 length bytes + 1 band byte + data length
	length := len(data) + 5
	if length > 65520 { // Max pkt-line length
		// Split into multiple packets
		for len(data) > 0 {
			chunk := data
			if len(chunk) > 65515 {
				chunk = data[:65515]
			}
			if err := s.writePacket(band, chunk); err != nil {
				return err
			}
			data = data[len(chunk):]
		}
		return nil
	}
	return s.writePacket(band, data)
}

func (s *SidebandWriter) writePacket(band byte, data string) error {
	length := len(data) + 5
	pkt := fmt.Sprintf("%04x%c%s", length, band, data)
	_, err := s.w.Write([]byte(pkt))
	return err
}

// WriteEmptyPackfile sends an empty packfile via sideband data channel
// This is required to properly terminate the git protocol after sending progress messages
func (s *SidebandWriter) WriteEmptyPackfile() error {
	// Empty packfile structure:
	// - 4 bytes: "PACK" signature
	// - 4 bytes: version 2 (big-endian)
	// - 4 bytes: object count 0 (big-endian)
	// - 20 bytes: SHA-1 checksum of the header

	// Pre-computed empty packfile (header + SHA-1 of header)
	// SHA-1("PACK\x00\x00\x00\x02\x00\x00\x00\x00") = 029d08823bd8a8eab510ad6ac75c823cfd3ed31e
	emptyPack := []byte{
		'P', 'A', 'C', 'K', // Signature
		0, 0, 0, 2, // Version 2
		0, 0, 0, 0, // 0 objects
		// SHA-1 checksum
		0x02, 0x9d, 0x08, 0x82, 0x3b, 0xd8, 0xa8, 0xea,
		0xb5, 0x10, 0xad, 0x6a, 0xc7, 0x5c, 0x82, 0x3c,
		0xfd, 0x3e, 0xd3, 0x1e,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Send pack data via sideband channel 1
	length := len(emptyPack) + 5
	pkt := fmt.Sprintf("%04x%c", length, SidebandData)
	if _, err := s.w.Write([]byte(pkt)); err != nil {
		return err
	}
	_, err := s.w.Write(emptyPack)
	return err
}

// Flush writes a flush packet (0000) to signal end of stream
func (s *SidebandWriter) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.w.Write([]byte("0000"))
	return err
}

// Color returns a colored string if colors are enabled
func (s *SidebandWriter) Color(color, text string) string {
	if !s.useColors {
		return text
	}
	return color + text + Reset
}

// Bold returns bold text if colors are enabled
func (s *SidebandWriter) Bold(text string) string {
	return s.Color(Bold, text)
}

// ReportWriter provides high-level methods for writing scan reports
type ReportWriter struct {
	sb *SidebandWriter
}

// NewReportWriter creates a new report writer
func NewReportWriter(sb *SidebandWriter) *ReportWriter {
	return &ReportWriter{sb: sb}
}

// Box drawing characters
const (
	BoxTopLeft     = "╔"
	BoxTopRight    = "╗"
	BoxBottomLeft  = "╚"
	BoxBottomRight = "╝"
	BoxHorizontal  = "═"
	BoxVertical    = "║"
	BoxMiddleLeft  = "╠"
	BoxMiddleRight = "╣"
)

// Plain box drawing characters (ASCII fallback)
const (
	PlainBoxTopLeft     = "+"
	PlainBoxTopRight    = "+"
	PlainBoxBottomLeft  = "+"
	PlainBoxBottomRight = "+"
	PlainBoxHorizontal  = "-"
	PlainBoxVertical    = "|"
	PlainBoxMiddleLeft  = "+"
	PlainBoxMiddleRight = "+"
)

// WriteBoxTop writes the top of a box
func (r *ReportWriter) WriteBoxTop(width int) error {
	line := BoxTopLeft + strings.Repeat(BoxHorizontal, width-2) + BoxTopRight
	return r.sb.WriteProgress(line)
}

// WriteBoxBottom writes the bottom of a box
func (r *ReportWriter) WriteBoxBottom(width int) error {
	line := BoxBottomLeft + strings.Repeat(BoxHorizontal, width-2) + BoxBottomRight
	return r.sb.WriteProgress(line)
}

// WriteBoxMiddle writes a middle separator line
func (r *ReportWriter) WriteBoxMiddle(width int) error {
	line := BoxMiddleLeft + strings.Repeat(BoxHorizontal, width-2) + BoxMiddleRight
	return r.sb.WriteProgress(line)
}

// WriteBoxLine writes a line inside the box
func (r *ReportWriter) WriteBoxLine(content string, width int) error {
	// Calculate available space for content
	maxContentWidth := width - 4 // 4 = 2 box chars + 2 spaces
	contentLen := visibleLength(content)

	// Truncate content if it's too long
	if contentLen > maxContentWidth {
		content = truncateWithEllipsis(content, maxContentWidth)
		contentLen = visibleLength(content)
	}

	// Calculate padding
	padding := width - 4 - contentLen
	if padding < 0 {
		padding = 0
	}
	line := BoxVertical + " " + content + strings.Repeat(" ", padding) + " " + BoxVertical
	return r.sb.WriteProgress(line)
}

// WriteBoxLineCentered writes a centered line inside the box
func (r *ReportWriter) WriteBoxLineCentered(content string, width int) error {
	contentLen := visibleLength(content)
	totalPadding := width - 4 - contentLen
	leftPad := totalPadding / 2
	rightPad := totalPadding - leftPad
	if leftPad < 0 {
		leftPad = 0
	}
	if rightPad < 0 {
		rightPad = 0
	}
	line := BoxVertical + " " + strings.Repeat(" ", leftPad) + content + strings.Repeat(" ", rightPad) + " " + BoxVertical
	return r.sb.WriteProgress(line)
}

// Spinner frames for progress animation
var SpinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Severity icons
const (
	IconInfoLeak = "🚨"
	IconCritical = "✗"
	IconHigh     = "⚠"
	IconMedium   = "◆"
	IconLow      = "○"
	IconInfo     = "ℹ"
	IconSuccess  = "✓"
)

// Plain severity icons (ASCII fallback)
const (
	PlainIconInfoLeak = "[!LEAK!]"
	PlainIconCritical = "[X]"
	PlainIconHigh     = "[!]"
	PlainIconMedium   = "[*]"
	PlainIconLow      = "[-]"
	PlainIconInfo     = "[i]"
	PlainIconSuccess  = "[+]"
)

// visibleLength calculates the visible length of a string, ignoring ANSI codes
func visibleLength(s string) int {
	inEscape := false
	length := 0
	for _, r := range s {
		if r == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		length++
	}
	return length
}

// truncateWithEllipsis truncates a string to maxLen visible characters,
// preserving ANSI color codes and adding "..." at the end
func truncateWithEllipsis(s string, maxLen int) string {
	if maxLen < 3 {
		return "..."
	}

	visLen := visibleLength(s)
	if visLen <= maxLen {
		return s
	}

	// We need to truncate. Build result preserving ANSI codes.
	var result strings.Builder
	inEscape := false
	visCount := 0
	targetLen := maxLen - 3 // Reserve space for "..."

	for _, r := range s {
		// Check for ANSI escape sequence
		if r == '\033' {
			inEscape = true
			result.WriteRune(r)
			continue
		}
		if inEscape {
			result.WriteRune(r)
			if r == 'm' {
				inEscape = false
			}
			continue
		}

		// Regular character
		if visCount < targetLen {
			result.WriteRune(r)
			visCount++
		} else {
			break
		}
	}

	result.WriteString("...")
	return result.String()
}
