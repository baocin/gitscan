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
