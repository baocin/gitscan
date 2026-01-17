package scanner

import (
	"encoding/json"
	"testing"
	"time"
)

// Sample SARIF output from opengrep
const sampleSARIF = `{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "opengrep",
          "semanticVersion": "1.0.0",
          "rules": [
            {
              "id": "go.lang.security.audit.xss.no-direct-write-to-responsewriter",
              "name": "no-direct-write-to-responsewriter",
              "shortDescription": {
                "text": "Detected directly writing to the http.ResponseWriter"
              },
              "defaultConfiguration": {
                "level": "warning"
              }
            },
            {
              "id": "javascript.lang.security.audit.sqli",
              "name": "sql-injection",
              "shortDescription": {
                "text": "SQL injection vulnerability detected"
              },
              "defaultConfiguration": {
                "level": "error"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "go.lang.security.audit.xss.no-direct-write-to-responsewriter",
          "level": "warning",
          "message": {
            "text": "Detected directly writing to the http.ResponseWriter"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "internal/handler.go"
                },
                "region": {
                  "startLine": 42,
                  "endLine": 42,
                  "startColumn": 2,
                  "endColumn": 45,
                  "snippet": {
                    "text": "w.Write([]byte(userInput))"
                  }
                }
              }
            }
          ]
        },
        {
          "ruleId": "javascript.lang.security.audit.sqli",
          "level": "error",
          "message": {
            "text": "Possible SQL injection"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/db.js"
                },
                "region": {
                  "startLine": 15,
                  "endLine": 15,
                  "startColumn": 1,
                  "endColumn": 50,
                  "snippet": {
                    "text": "db.query('SELECT * FROM users WHERE id = ' + id)"
                  }
                }
              }
            }
          ]
        }
      ]
    }
  ]
}`

func TestParseSARIFOutput(t *testing.T) {
	result, err := parseSARIFOutput(sampleSARIF, 100, time.Now())
	if err != nil {
		t.Fatalf("Failed to parse SARIF output: %v", err)
	}

	// Verify we got the right number of findings
	if len(result.Findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(result.Findings))
	}

	// Verify severity counts
	if result.CriticalCount != 1 {
		t.Errorf("Expected 1 critical finding (from 'error' level), got %d", result.CriticalCount)
	}
	if result.HighCount != 1 {
		t.Errorf("Expected 1 high finding (from 'warning' level), got %d", result.HighCount)
	}

	// Verify FindingsJSON is valid JSON array
	if result.FindingsJSON == "" {
		t.Error("FindingsJSON should not be empty")
	}

	var parsedFindings []Finding
	if err := json.Unmarshal([]byte(result.FindingsJSON), &parsedFindings); err != nil {
		t.Fatalf("FindingsJSON is not valid JSON: %v", err)
	}

	if len(parsedFindings) != 2 {
		t.Errorf("Expected 2 findings in JSON, got %d", len(parsedFindings))
	}

	// Verify first finding details
	f1 := parsedFindings[0]
	if f1.RuleID != "go.lang.security.audit.xss.no-direct-write-to-responsewriter" {
		t.Errorf("Unexpected rule ID: %s", f1.RuleID)
	}
	if f1.Severity != "high" { // warning -> high
		t.Errorf("Expected severity 'high', got '%s'", f1.Severity)
	}
	if f1.Path != "internal/handler.go" {
		t.Errorf("Expected path 'internal/handler.go', got '%s'", f1.Path)
	}
	if f1.StartLine != 42 {
		t.Errorf("Expected start line 42, got %d", f1.StartLine)
	}

	// Verify second finding details
	f2 := parsedFindings[1]
	if f2.RuleID != "javascript.lang.security.audit.sqli" {
		t.Errorf("Unexpected rule ID: %s", f2.RuleID)
	}
	if f2.Severity != "critical" { // error -> critical
		t.Errorf("Expected severity 'critical', got '%s'", f2.Severity)
	}
	if f2.Snippet != "db.query('SELECT * FROM users WHERE id = ' + id)" {
		t.Errorf("Unexpected snippet: %s", f2.Snippet)
	}
}

func TestParseSARIFOutputEmpty(t *testing.T) {
	result, err := parseSARIFOutput("", 50, time.Now())
	if err != nil {
		t.Fatalf("Failed to parse empty SARIF: %v", err)
	}

	if result.FindingsJSON != "[]" {
		t.Errorf("Expected empty array '[]', got '%s'", result.FindingsJSON)
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(result.Findings))
	}

	if result.FilesScanned != 50 {
		t.Errorf("Expected 50 files scanned, got %d", result.FilesScanned)
	}
}

func TestParseSARIFOutputNoResults(t *testing.T) {
	noResultsSARIF := `{
		"version": "2.1.0",
		"runs": [{"tool": {"driver": {"name": "opengrep"}}, "results": []}]
	}`

	result, err := parseSARIFOutput(noResultsSARIF, 25, time.Now())
	if err != nil {
		t.Fatalf("Failed to parse SARIF with no results: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(result.Findings))
	}

	if result.FindingsJSON != "[]" {
		t.Errorf("Expected empty array '[]', got '%s'", result.FindingsJSON)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"error", "critical"},
		{"ERROR", "critical"},
		{"critical", "critical"},
		{"CRITICAL", "critical"},
		{"warning", "high"},
		{"WARNING", "high"},
		{"high", "high"},
		{"HIGH", "high"},
		{"note", "medium"},
		{"NOTE", "medium"},
		{"medium", "medium"},
		{"MEDIUM", "medium"},
		{"info", "low"},
		{"INFO", "low"},
		{"low", "low"},
		{"LOW", "low"},
		{"unknown", "info"},
		{"", "info"},
	}

	for _, tc := range tests {
		result := normalizeSeverity(tc.input)
		if result != tc.expected {
			t.Errorf("normalizeSeverity(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestFindingsJSONCanBeUnmarshaledAsArray(t *testing.T) {
	// This test verifies the fix for the bug where SARIF was stored directly
	// but handlers expected []Finding format
	result, err := parseSARIFOutput(sampleSARIF, 100, time.Now())
	if err != nil {
		t.Fatalf("Failed to parse SARIF: %v", err)
	}

	// Simulate what the handlers do: unmarshal as []Finding
	var findings []Finding
	if err := json.Unmarshal([]byte(result.FindingsJSON), &findings); err != nil {
		t.Fatalf("Handler-style unmarshal failed: %v\nFindingsJSON was: %s", err, result.FindingsJSON)
	}

	// Verify all expected fields are present
	for i, f := range findings {
		if f.RuleID == "" {
			t.Errorf("Finding %d missing RuleID", i)
		}
		if f.Severity == "" {
			t.Errorf("Finding %d missing Severity", i)
		}
		if f.Message == "" {
			t.Errorf("Finding %d missing Message", i)
		}
		if f.Path == "" {
			t.Errorf("Finding %d missing Path", i)
		}
		if f.StartLine == 0 {
			t.Errorf("Finding %d missing StartLine", i)
		}
	}
}
