package license

import (
	"os"
	"path/filepath"
	"strings"
)

// License file names to check, in order of priority
var licenseFiles = []string{
	"LICENSE",
	"LICENSE.txt",
	"LICENSE.md",
	"LICENSE.rst",
	"LICENCE",
	"LICENCE.txt",
	"LICENCE.md",
	"COPYING",
	"COPYING.txt",
	"license",
	"license.txt",
	"license.md",
}

// LicenseInfo holds information about a detected license
type LicenseInfo struct {
	Type     string // e.g., "MIT", "Apache-2.0", "GPL-3.0", "Unknown"
	FilePath string // Path to the license file
}

// Detect attempts to detect the license of a repository
func Detect(repoPath string) *LicenseInfo {
	for _, filename := range licenseFiles {
		path := filepath.Join(repoPath, filename)
		if content, err := os.ReadFile(path); err == nil {
			licenseType := identifyLicense(string(content))
			return &LicenseInfo{
				Type:     licenseType,
				FilePath: filename,
			}
		}
	}

	// Check for package.json license field
	packageJSON := filepath.Join(repoPath, "package.json")
	if content, err := os.ReadFile(packageJSON); err == nil {
		if license := extractJSONLicense(string(content)); license != "" {
			return &LicenseInfo{
				Type:     license,
				FilePath: "package.json",
			}
		}
	}

	return nil
}

// identifyLicense identifies the license type from content
func identifyLicense(content string) string {
	contentLower := strings.ToLower(content)

	// MIT License
	if strings.Contains(contentLower, "mit license") ||
		strings.Contains(contentLower, "permission is hereby granted, free of charge") {
		return "MIT"
	}

	// Apache 2.0
	if strings.Contains(contentLower, "apache license") &&
		strings.Contains(contentLower, "version 2.0") {
		return "Apache-2.0"
	}

	// GPL v3
	if strings.Contains(contentLower, "gnu general public license") &&
		strings.Contains(contentLower, "version 3") {
		return "GPL-3.0"
	}

	// GPL v2
	if strings.Contains(contentLower, "gnu general public license") &&
		strings.Contains(contentLower, "version 2") {
		return "GPL-2.0"
	}

	// LGPL
	if strings.Contains(contentLower, "gnu lesser general public license") {
		if strings.Contains(contentLower, "version 3") {
			return "LGPL-3.0"
		}
		if strings.Contains(contentLower, "version 2") {
			return "LGPL-2.1"
		}
		return "LGPL"
	}

	// BSD 3-Clause
	if strings.Contains(contentLower, "bsd") &&
		strings.Contains(contentLower, "redistributions of source code") &&
		strings.Contains(contentLower, "neither the name") {
		return "BSD-3-Clause"
	}

	// BSD 2-Clause
	if strings.Contains(contentLower, "bsd") &&
		strings.Contains(contentLower, "redistributions of source code") &&
		!strings.Contains(contentLower, "neither the name") {
		return "BSD-2-Clause"
	}

	// ISC
	if strings.Contains(contentLower, "isc license") ||
		(strings.Contains(contentLower, "permission to use, copy, modify") &&
			strings.Contains(contentLower, "isc")) {
		return "ISC"
	}

	// MPL 2.0
	if strings.Contains(contentLower, "mozilla public license") &&
		strings.Contains(contentLower, "2.0") {
		return "MPL-2.0"
	}

	// Unlicense
	if strings.Contains(contentLower, "this is free and unencumbered software") ||
		strings.Contains(contentLower, "unlicense") {
		return "Unlicense"
	}

	// CC0
	if strings.Contains(contentLower, "cc0") ||
		strings.Contains(contentLower, "creative commons zero") {
		return "CC0-1.0"
	}

	// WTFPL
	if strings.Contains(contentLower, "do what the fuck you want to") ||
		strings.Contains(contentLower, "wtfpl") {
		return "WTFPL"
	}

	// Proprietary indicators
	if strings.Contains(contentLower, "all rights reserved") &&
		!strings.Contains(contentLower, "mit") &&
		!strings.Contains(contentLower, "bsd") {
		return "Proprietary"
	}

	return "Unknown"
}

// extractJSONLicense extracts license from package.json
func extractJSONLicense(content string) string {
	// Simple extraction without full JSON parsing
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, `"license"`) {
			// Extract value: "license": "MIT",
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				value := strings.TrimSpace(parts[1])
				value = strings.Trim(value, `",`)
				if value != "" {
					return value
				}
			}
		}
	}
	return ""
}

// ShortName returns a short display name for the license
func (l *LicenseInfo) ShortName() string {
	if l == nil {
		return "No License"
	}
	return l.Type
}
