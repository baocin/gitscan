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
	result, err := parseSARIFOutput(sampleSARIF, "", 100, time.Now(), false)
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
	result, err := parseSARIFOutput("", "", 50, time.Now(), false)
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

	result, err := parseSARIFOutput(noResultsSARIF, "", 25, time.Now(), false)
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
		result := normalizeSeverity(tc.input, "test-rule")
		if result != tc.expected {
			t.Errorf("normalizeSeverity(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestFindingsJSONCanBeUnmarshaledAsArray(t *testing.T) {
	// This test verifies the fix for the bug where SARIF was stored directly
	// but handlers expected []Finding format
	result, err := parseSARIFOutput(sampleSARIF, "", 100, time.Now(), false)
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

func TestCalculateRunRisk(t *testing.T) {
	tests := []struct {
		infoLeak, critical, high, medium, low int
		expectedScore                         int
	}{
		{0, 0, 0, 0, 0, 100},    // Perfect score
		{1, 0, 0, 0, 0, 60},     // 1 info-leak = -40
		{0, 1, 0, 0, 0, 75},     // 1 critical = -25
		{0, 0, 1, 0, 0, 85},     // 1 high = -15
		{0, 0, 0, 1, 0, 95},     // 1 medium = -5
		{0, 0, 0, 0, 1, 99},     // 1 low = -1
		{0, 1, 1, 1, 1, 54},     // -25 -15 -5 -1 = -46, so 54
		{1, 1, 1, 1, 1, 14},     // -40 -25 -15 -5 -1 = -86, so 14
		{0, 2, 2, 2, 2, 8},      // -50 -30 -10 -2 = -92, so 8
		{0, 4, 0, 0, 0, 0},      // 4 critical = -100, clamped to 0
		{3, 0, 0, 0, 0, 0},      // 3 info-leak = -120, clamped to 0
		{0, 0, 0, 0, 100, 0},    // 100 low = -100, clamped to 0
		{2, 10, 10, 10, 10, 0},  // Way over, clamped to 0
	}

	for _, tc := range tests {
		score := CalculateRunRisk(tc.infoLeak, tc.critical, tc.high, tc.medium, tc.low)
		if score != tc.expectedScore {
			t.Errorf("CalculateRunRisk(%d, %d, %d, %d, %d) = %d, expected %d",
				tc.infoLeak, tc.critical, tc.high, tc.medium, tc.low, score, tc.expectedScore)
		}
	}
}

func TestRiskGrade(t *testing.T) {
	tests := []struct {
		score         int
		expectedGrade string
	}{
		{100, "A"},
		{95, "A"},
		{90, "A"},
		{89, "B"},
		{80, "B"},
		{79, "C"},
		{70, "C"},
		{69, "D"},
		{60, "D"},
		{59, "F"},
		{50, "F"},
		{0, "F"},
	}

	for _, tc := range tests {
		grade := RiskGrade(tc.score)
		if grade != tc.expectedGrade {
			t.Errorf("RiskGrade(%d) = %q, expected %q", tc.score, grade, tc.expectedGrade)
		}
	}
}

func TestSecurityScoreInParsedResult(t *testing.T) {
	// Verify security score is calculated during SARIF parsing
	result, err := parseSARIFOutput(sampleSARIF, "", 100, time.Now(), false)
	if err != nil {
		t.Fatalf("Failed to parse SARIF: %v", err)
	}

	// Sample SARIF has: 1 critical (error), 1 high (warning)
	// Expected: 100 - 25 - 15 = 60
	expectedScore := CalculateRunRisk(result.InfoLeakCount, result.CriticalCount, result.HighCount, result.MediumCount, result.LowCount)
	if result.SecurityScore != expectedScore {
		t.Errorf("SecurityScore = %d, expected %d", result.SecurityScore, expectedScore)
	}
}
