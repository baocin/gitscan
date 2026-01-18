// Package version contains version constants for gitscan and its dependencies.
package version

// Opengrep version pinned for consistent scanning results.
// Update this version carefully - SARIF output format may change between versions.
//
// To update:
// 1. Test the new version locally
// 2. Verify SARIF parsing still works
// 3. Update this constant
// 4. Update docker/Dockerfile
// 5. Update .github/workflows/test.yml
const (
	// OpenGrepVersion is the pinned version of opengrep for consistent scanning.
	// See: https://github.com/opengrep/opengrep/releases
	OpenGrepVersion = "1.15.1"

	// MinimumGoVersion is the minimum supported Go version.
	MinimumGoVersion = "1.22"
)
