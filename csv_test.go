package main

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"
)

func TestStringOrNA(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"", "N/A"},
	}
	for _, tt := range tests {
		got := stringOrNA(tt.input)
		if got != tt.want {
			t.Errorf("stringOrNA(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestJoinOrNA(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{"non-empty", []string{"a", "b"}, "a, b"},
		{"single", []string{"x"}, "x"},
		{"empty", []string{}, "N/A"},
		{"nil", nil, "N/A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := joinOrNA(tt.input)
			if got != tt.want {
				t.Errorf("joinOrNA(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRemoveDuplicates(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  int
	}{
		{"no dupes", []string{"a", "b", "c"}, 3},
		{"with dupes", []string{"a", "b", "a", "c", "b"}, 3},
		{"all same", []string{"x", "x", "x"}, 1},
		{"empty", []string{}, 0},
		{"filters empty strings", []string{"a", "", "b", ""}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := removeDuplicates(tt.input)
			if len(got) != tt.want {
				t.Errorf("removeDuplicates(%v) returned %d items, want %d", tt.input, len(got), tt.want)
			}
		})
	}
}

func TestBoolToYesNo(t *testing.T) {
	if got := boolToYesNo(true); got != "Yes" {
		t.Errorf("boolToYesNo(true) = %q, want Yes", got)
	}
	if got := boolToYesNo(false); got != "No" {
		t.Errorf("boolToYesNo(false) = %q, want No", got)
	}
}

func TestBuildCSVRow(t *testing.T) {
	columns := []string{"A", "B", "C"}
	data := map[string]string{"A": "1", "C": "3"}

	row := buildCSVRow(columns, data)
	if len(row) != 3 {
		t.Fatalf("expected 3 columns, got %d", len(row))
	}
	if row[0] != "1" {
		t.Errorf("expected row[0] = '1', got %q", row[0])
	}
	if row[1] != "N/A" {
		t.Errorf("expected row[1] = 'N/A' for missing key, got %q", row[1])
	}
	if row[2] != "3" {
		t.Errorf("expected row[2] = '3', got %q", row[2])
	}
}

func TestWriteCSVOutput(t *testing.T) {
	results := ScanResults{
		Timestamp:  "2026-01-01T00:00:00Z",
		TotalIPs:   1,
		ScannedIPs: 1,
		IPResults: []IPResult{{
			IP:     "10.0.0.1",
			Status: "scanned",
			PortResults: []PortResult{{
				Port:        443,
				Protocol:    "tcp",
				State:       "open",
				Service:     "ssl/tls",
				Status:      StatusOK,
				Reason:      "TLS scan successful",
				TlsVersions: []string{"TLSv1.2", "TLSv1.3"},
				TlsCiphers:  []string{"TLS_AES_128_GCM_SHA256"},
			}},
		}},
	}

	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "results.csv")

	err := writeCSVOutput(results, csvPath)
	if err != nil {
		t.Fatalf("writeCSVOutput failed: %v", err)
	}

	f, err := os.Open(csvPath)
	if err != nil {
		t.Fatalf("failed to open CSV: %v", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("failed to read CSV: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 rows (header + data), got %d", len(records))
	}

	header := records[0]
	if header[0] != "IP" {
		t.Errorf("expected first column header 'IP', got %q", header[0])
	}

	dataRow := records[1]
	if dataRow[0] != "10.0.0.1" {
		t.Errorf("expected IP '10.0.0.1', got %q", dataRow[0])
	}
	if dataRow[1] != "443" {
		t.Errorf("expected port '443', got %q", dataRow[1])
	}
}

func TestWriteCSVOutputMultiplePorts(t *testing.T) {
	results := ScanResults{
		IPResults: []IPResult{{
			IP: "10.0.0.1",
			PortResults: []PortResult{
				{Port: 443, Protocol: "tcp", Status: StatusOK},
				{Port: 8443, Protocol: "tcp", Status: StatusNoTLS},
			},
		}},
	}

	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "multi.csv")

	if err := writeCSVOutput(results, csvPath); err != nil {
		t.Fatalf("writeCSVOutput failed: %v", err)
	}

	f, _ := os.Open(csvPath)
	defer f.Close()
	records, _ := csv.NewReader(f).ReadAll()

	if len(records) != 3 {
		t.Errorf("expected 3 rows (header + 2 data), got %d", len(records))
	}
}

func TestWriteCSVOutputPQCColumns(t *testing.T) {
	results := ScanResults{
		IPResults: []IPResult{{
			IP: "10.0.0.1",
			PortResults: []PortResult{{
				Port:           443,
				Protocol:       "tcp",
				Status:         StatusOK,
				TLS13Supported: true,
				MLKEMSupported: true,
				MLKEMCiphers:   []string{"x25519mlkem768"},
				AllKEMs:        []string{"x25519mlkem768", "x25519"},
			}},
		}},
	}

	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "pqc.csv")

	if err := writeCSVOutput(results, csvPath); err != nil {
		t.Fatalf("writeCSVOutput failed: %v", err)
	}

	f, _ := os.Open(csvPath)
	defer f.Close()
	records, _ := csv.NewReader(f).ReadAll()

	header := records[0]
	dataRow := records[1]

	tls13Idx := -1
	mlkemIdx := -1
	for i, col := range header {
		if col == "TLS 1.3 Supported" {
			tls13Idx = i
		}
		if col == "ML-KEM Supported" {
			mlkemIdx = i
		}
	}

	if tls13Idx == -1 || mlkemIdx == -1 {
		t.Fatal("expected TLS 1.3 Supported and ML-KEM Supported columns in header")
	}
	if dataRow[tls13Idx] != "Yes" {
		t.Errorf("expected TLS 1.3 Supported = 'Yes', got %q", dataRow[tls13Idx])
	}
	if dataRow[mlkemIdx] != "Yes" {
		t.Errorf("expected ML-KEM Supported = 'Yes', got %q", dataRow[mlkemIdx])
	}
}

func TestWriteScanErrorsCSV(t *testing.T) {
	t.Run("no errors produces no file", func(t *testing.T) {
		results := ScanResults{}
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "errors.csv")

		err := writeScanErrorsCSV(results, path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Error("expected no file to be created when there are no errors")
		}
	})

	t.Run("writes errors to CSV", func(t *testing.T) {
		results := ScanResults{
			ScanErrors: []ScanError{
				{IP: "10.0.0.1", Port: 443, ErrorType: "scan_failed", ErrorMsg: "timeout"},
			},
		}
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "errors.csv")

		if err := writeScanErrorsCSV(results, path); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		f, _ := os.Open(path)
		defer f.Close()
		records, _ := csv.NewReader(f).ReadAll()

		if len(records) != 2 {
			t.Errorf("expected 2 rows, got %d", len(records))
		}
		if records[1][0] != "10.0.0.1" {
			t.Errorf("expected IP '10.0.0.1', got %q", records[1][0])
		}
	})
}
