package cache

import (
	"errors"
	"testing"
	"time"
)

func TestClassifyCloneError(t *testing.T) {
	tests := []struct {
		name         string
		output       string
		expectedType error
	}{
		{
			name:         "repository not found",
			output:       "fatal: repository 'https://github.com/nonexistent/repo' not found",
			expectedType: ErrRepoNotFound,
		},
		{
			name:         "remote repository not found",
			output:       "remote: Repository not found.\nfatal: repository 'https://github.com/user/repo' not found",
			expectedType: ErrRepoNotFound,
		},
		{
			name:         "authentication failed",
			output:       "fatal: Authentication failed for 'https://github.com/private/repo'",
			expectedType: ErrRepoPrivate,
		},
		{
			name:         "permission denied",
			output:       "fatal: unable to access 'https://github.com/private/repo/': Permission denied",
			expectedType: ErrRepoPrivate,
		},
		{
			name:         "403 forbidden",
			output:       "fatal: unable to access 'https://github.com/user/repo': The requested URL returned error: 403",
			expectedType: ErrRepoPrivate,
		},
		{
			name:         "could not resolve host",
			output:       "fatal: unable to access 'https://invalid.example.com/repo': Could not resolve host: invalid.example.com",
			expectedType: ErrNetworkError,
		},
		{
			name:         "connection refused",
			output:       "fatal: unable to access 'https://localhost:9999/repo': Connection refused",
			expectedType: ErrNetworkError,
		},
		{
			name:         "network unreachable",
			output:       "fatal: unable to access 'https://example.com/repo': Network is unreachable",
			expectedType: ErrNetworkError,
		},
		{
			name:         "rate limited",
			output:       "fatal: unable to access 'https://github.com/repo': Too many requests (429)",
			expectedType: ErrRateLimited,
		},
		{
			name:         "invalid URL",
			output:       "fatal: repository 'not-a-valid-url' does not exist\nfatal: invalid url",
			expectedType: ErrInvalidURL,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyCloneError(tc.output, errors.New("git error"), "https://example.com/repo", 30*time.Second)

			var repoErr *RepoError
			if !errors.As(err, &repoErr) {
				t.Fatalf("Expected RepoError, got %T", err)
			}

			if !errors.Is(repoErr.Type, tc.expectedType) {
				t.Errorf("Expected error type %v, got %v", tc.expectedType, repoErr.Type)
			}

			if repoErr.Message == "" {
				t.Error("Expected non-empty error message")
			}

			if repoErr.Details == "" {
				t.Error("Expected non-empty details")
			}
		})
	}
}

func TestClassifyCloneErrorDefaultCase(t *testing.T) {
	// Test that unknown errors are handled gracefully
	output := "fatal: some unknown git error that we don't recognize"
	originalErr := errors.New("git error")

	err := classifyCloneError(output, originalErr, "https://example.com/repo", 30*time.Second)

	var repoErr *RepoError
	if !errors.As(err, &repoErr) {
		t.Fatalf("Expected RepoError, got %T", err)
	}

	// Should have the original error as Type
	if repoErr.Type != originalErr {
		t.Errorf("Expected original error as type, got %v", repoErr.Type)
	}

	// Message should contain the first line
	if repoErr.Message == "" {
		t.Error("Expected non-empty message for unknown errors")
	}
}

func TestFirstLine(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "fatal: repository not found",
			expected: "repository not found",
		},
		{
			input:    "error: something went wrong\nmore details here",
			expected: "something went wrong",
		},
		{
			input:    "remote: Repository not found.\nfatal: authentication failed",
			expected: "Repository not found.",
		},
		{
			input:    "\n\n  fatal: some error  \n",
			expected: "some error",
		},
		{
			input:    "",
			expected: "unknown error",
		},
		{
			input:    "   \n  \n  ",
			expected: "unknown error",
		},
	}

	for _, tc := range tests {
		result := firstLine(tc.input)
		if result != tc.expected {
			t.Errorf("firstLine(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestRepoErrorImplementsError(t *testing.T) {
	err := &RepoError{
		Type:    ErrRepoNotFound,
		Message: "test message",
		Details: "test details",
	}

	// Check Error() method
	if err.Error() != "test message" {
		t.Errorf("Error() = %q, expected %q", err.Error(), "test message")
	}

	// Check Unwrap() method
	if err.Unwrap() != ErrRepoNotFound {
		t.Errorf("Unwrap() = %v, expected %v", err.Unwrap(), ErrRepoNotFound)
	}

	// Check that errors.Is works
	if !errors.Is(err, ErrRepoNotFound) {
		t.Error("errors.Is(err, ErrRepoNotFound) should be true")
	}
}

// TestClassifyCloneErrorMistypedRepos tests error classification for common typo scenarios
func TestClassifyCloneErrorMistypedRepos(t *testing.T) {
	tests := []struct {
		name         string
		output       string
		description  string
		expectedType error
	}{
		{
			name:         "github_404_not_found",
			output:       "Cloning into 'repo'...\nremote: Not Found\nfatal: repository 'https://github.com/baocin/gitscam/' not found",
			description:  "Mistyped repo name - GitHub returns 404",
			expectedType: ErrRepoNotFound,
		},
		{
			name:         "github_private_or_nonexistent",
			output:       "Cloning into 'repo'...\nremote: Repository not found.\nfatal: Authentication failed for 'https://github.com/baocn/gitscan.git/'",
			description:  "Mistyped owner - GitHub says not found then auth failed",
			expectedType: ErrRepoNotFound, // "Repository not found" message takes precedence
		},
		{
			name:         "gitlab_404",
			output:       "Cloning into 'repo'...\nremote: The project you were looking for could not be found.\nfatal: Could not read from remote repository.",
			description:  "GitLab non-existent project",
			expectedType: ErrRepoNotFound,
		},
		{
			name:         "bitbucket_404",
			output:       "Cloning into 'repo'...\nfatal: repository 'https://bitbucket.org/user/nonexistent-repo/' not found",
			description:  "Bitbucket non-existent repo",
			expectedType: ErrRepoNotFound,
		},
		{
			name:         "host_typo_dns_fail",
			output:       "Cloning into 'repo'...\nfatal: unable to access 'https://githbu.com/baocin/gitscan/': Could not resolve host: githbu.com",
			description:  "Typo in hostname causes DNS failure",
			expectedType: ErrNetworkError,
		},
		{
			name:         "username_prompt_for_private",
			output:       "Cloning into 'repo'...\nfatal: could not read Username for 'https://github.com': terminal prompts disabled",
			description:  "Private repo prompts for username",
			expectedType: ErrRepoPrivate,
		},
		{
			name:         "password_prompt_for_private",
			output:       "Cloning into 'repo'...\nfatal: could not read Password for 'https://github.com': terminal prompts disabled",
			description:  "Private repo prompts for password",
			expectedType: ErrRepoPrivate,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyCloneError(tc.output, errors.New("git error"), "https://example.com/repo", 30*time.Second)

			var repoErr *RepoError
			if !errors.As(err, &repoErr) {
				t.Fatalf("Expected RepoError for %s, got %T", tc.description, err)
			}

			if !errors.Is(repoErr.Type, tc.expectedType) {
				t.Errorf("%s: Expected error type %v, got %v\nOutput was: %s", tc.description, tc.expectedType, repoErr.Type, tc.output)
			}
		})
	}
}

// TestClassifyCloneErrorEdgeCases tests edge cases in error classification
func TestClassifyCloneErrorEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		output       string
		expectedType error
	}{
		{
			name:         "empty_output",
			output:       "",
			expectedType: nil, // Will use original error
		},
		{
			name:         "whitespace_only",
			output:       "   \n\n  \t  ",
			expectedType: nil, // Will use original error
		},
		{
			name:         "mixed_case_not_found",
			output:       "FATAL: REPOSITORY NOT FOUND",
			expectedType: ErrRepoNotFound,
		},
		{
			name:         "rate_limit_with_429",
			output:       "error: RPC failed; HTTP 429 Too Many Requests",
			expectedType: ErrRateLimited,
		},
		{
			name:         "rate_limit_github_style",
			output:       "fatal: unable to access: rate limit exceeded",
			expectedType: ErrRateLimited,
		},
		{
			name:         "connection_timeout",
			output:       "fatal: unable to access 'https://slow-server.com/repo': Connection timed out",
			expectedType: ErrNetworkError,
		},
		{
			name:         "ssl_error",
			output:       "fatal: unable to access 'https://example.com/repo': SSL certificate problem",
			expectedType: ErrNetworkError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			originalErr := errors.New("git error")
			err := classifyCloneError(tc.output, originalErr, "https://example.com/repo", 30*time.Second)

			var repoErr *RepoError
			if !errors.As(err, &repoErr) {
				t.Fatalf("Expected RepoError, got %T", err)
			}

			if tc.expectedType == nil {
				// Should fall back to original error
				if repoErr.Type != originalErr {
					t.Errorf("Expected original error as type for %q, got %v", tc.name, repoErr.Type)
				}
			} else {
				if !errors.Is(repoErr.Type, tc.expectedType) {
					t.Errorf("Expected error type %v for %q, got %v", tc.expectedType, tc.name, repoErr.Type)
				}
			}
		})
	}
}

// TestAllErrorSentinels verifies all error sentinels are distinct
func TestAllErrorSentinels(t *testing.T) {
	sentinels := []error{
		ErrRepoNotFound,
		ErrRepoPrivate,
		ErrNetworkError,
		ErrInvalidURL,
		ErrCloneTimeout,
		ErrRepoTooLarge,
		ErrRateLimited,
	}

	// Check that all sentinels have messages
	for _, sentinel := range sentinels {
		if sentinel.Error() == "" {
			t.Errorf("Sentinel %v has empty error message", sentinel)
		}
	}

	// Check that all sentinels are distinct
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i != j && errors.Is(a, b) {
				t.Errorf("Sentinels %v and %v are not distinct", a, b)
			}
		}
	}
}

// TestRepoErrorWithAllTypes tests RepoError with each sentinel type
func TestRepoErrorWithAllTypes(t *testing.T) {
	sentinels := []error{
		ErrRepoNotFound,
		ErrRepoPrivate,
		ErrNetworkError,
		ErrInvalidURL,
		ErrCloneTimeout,
		ErrRepoTooLarge,
		ErrRateLimited,
	}

	for _, sentinel := range sentinels {
		t.Run(sentinel.Error(), func(t *testing.T) {
			repoErr := &RepoError{
				Type:    sentinel,
				Message: "test message for " + sentinel.Error(),
				Details: "details",
			}

			// errors.Is should work through Unwrap
			if !errors.Is(repoErr, sentinel) {
				t.Errorf("errors.Is failed for %v", sentinel)
			}

			// errors.As should work
			var target *RepoError
			if !errors.As(repoErr, &target) {
				t.Errorf("errors.As failed for %v", sentinel)
			}

			if target.Type != sentinel {
				t.Errorf("Type mismatch after errors.As: got %v, want %v", target.Type, sentinel)
			}
		})
	}
}
