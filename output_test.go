package main

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteJSONOutput(t *testing.T) {
	results := ScanResults{
		Timestamp:  "2026-01-01T00:00:00Z",
		TotalIPs:   1,
		ScannedIPs: 1,
		IPResults: []IPResult{{
			IP:     "10.0.0.1",
			Status: "scanned",
			PortResults: []PortResult{{
				Port:     443,
				Protocol: "tcp",
				State:    "open",
				Service:  "ssl/tls",
				Status:   StatusOK,
			}},
		}},
	}

	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "results.json")

	if err := writeJSONOutput(results, jsonPath); err != nil {
		t.Fatalf("writeJSONOutput failed: %v", err)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read JSON file: %v", err)
	}

	var parsed ScanResults
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if parsed.Timestamp != "2026-01-01T00:00:00Z" {
		t.Errorf("expected timestamp '2026-01-01T00:00:00Z', got %q", parsed.Timestamp)
	}
	if len(parsed.IPResults) != 1 {
		t.Fatalf("expected 1 IP result, got %d", len(parsed.IPResults))
	}
	if parsed.IPResults[0].IP != "10.0.0.1" {
		t.Errorf("expected IP '10.0.0.1', got %q", parsed.IPResults[0].IP)
	}
	if parsed.IPResults[0].PortResults[0].Port != 443 {
		t.Errorf("expected port 443, got %d", parsed.IPResults[0].PortResults[0].Port)
	}
}

func TestWriteJUnitOutput(t *testing.T) {
	results := ScanResults{
		IPResults: []IPResult{{
			IP:  "10.0.0.1",
			Pod: &PodInfo{Name: "test-pod", Namespace: "default"},
			PortResults: []PortResult{{
				Port:    443,
				Service: "ssl/tls",
				IngressTLSConfigCompliance: &TLSConfigComplianceResult{
					Version: true,
					Ciphers: true,
				},
			}},
		}},
	}

	tmpDir := t.TempDir()
	junitPath := filepath.Join(tmpDir, "results.xml")

	if err := writeJUnitOutput(results, junitPath); err != nil {
		t.Fatalf("writeJUnitOutput failed: %v", err)
	}

	data, err := os.ReadFile(junitPath)
	if err != nil {
		t.Fatalf("failed to read JUnit file: %v", err)
	}

	var suite JUnitTestSuite
	if err := xml.Unmarshal(data, &suite); err != nil {
		t.Fatalf("failed to parse JUnit XML: %v", err)
	}

	if suite.Name != "TLSSecurityScan" {
		t.Errorf("expected suite name 'TLSSecurityScan', got %q", suite.Name)
	}
	if suite.Tests != 1 {
		t.Errorf("expected 1 test, got %d", suite.Tests)
	}
	if suite.Failures != 0 {
		t.Errorf("expected 0 failures, got %d", suite.Failures)
	}
}

func TestWriteJUnitOutputWithFailures(t *testing.T) {
	results := ScanResults{
		IPResults: []IPResult{{
			IP:  "10.0.0.1",
			Pod: &PodInfo{Name: "test-pod", Namespace: "default"},
			PortResults: []PortResult{{
				Port:    443,
				Service: "ssl/tls",
				IngressTLSConfigCompliance: &TLSConfigComplianceResult{
					Version: false,
					Ciphers: true,
				},
				APIServerTLSConfigCompliance: &TLSConfigComplianceResult{
					Version: true,
					Ciphers: false,
				},
			}},
		}},
	}

	tmpDir := t.TempDir()
	junitPath := filepath.Join(tmpDir, "failures.xml")

	if err := writeJUnitOutput(results, junitPath); err != nil {
		t.Fatalf("writeJUnitOutput failed: %v", err)
	}

	data, _ := os.ReadFile(junitPath)
	var suite JUnitTestSuite
	xml.Unmarshal(data, &suite)

	if suite.Failures != 1 {
		t.Errorf("expected 1 failure, got %d", suite.Failures)
	}
	if suite.TestCases[0].Failure == nil {
		t.Fatal("expected test case to have a failure")
	}
	if suite.TestCases[0].Failure.Type != "TLSComplianceCheck" {
		t.Errorf("expected failure type 'TLSComplianceCheck', got %q", suite.TestCases[0].Failure.Type)
	}
}

func TestWriteOutputFiles(t *testing.T) {
	results := ScanResults{
		Timestamp:  "2026-01-01T00:00:00Z",
		TotalIPs:   1,
		ScannedIPs: 1,
		IPResults: []IPResult{{
			IP:     "10.0.0.1",
			Status: "scanned",
			PortResults: []PortResult{{
				Port:    443,
				Status:  StatusOK,
				Service: "ssl/tls",
			}},
			Pod: &PodInfo{Name: "test-pod"},
		}},
	}

	t.Run("does nothing when no files specified", func(t *testing.T) {
		tmpDir := t.TempDir()
		writeOutputFiles(results, tmpDir, "", "", "")
		entries, _ := os.ReadDir(tmpDir)
		if len(entries) != 0 {
			t.Errorf("expected empty dir, got %d entries", len(entries))
		}
	})

	t.Run("writes all three output files", func(t *testing.T) {
		tmpDir := t.TempDir()
		writeOutputFiles(results, tmpDir, "out.json", "out.csv", "out.xml")

		for _, name := range []string{"out.json", "out.csv", "out.xml"} {
			path := filepath.Join(tmpDir, name)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				t.Errorf("expected file %s to exist", name)
			}
		}
	})

	t.Run("handles absolute paths", func(t *testing.T) {
		tmpDir := t.TempDir()
		absJSON := filepath.Join(tmpDir, "absolute.json")
		writeOutputFiles(results, tmpDir, absJSON, "", "")

		if _, err := os.Stat(absJSON); os.IsNotExist(err) {
			t.Error("expected absolute path JSON file to exist")
		}
	})
}
