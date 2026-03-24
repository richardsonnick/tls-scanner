package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openshift/tls-scanner/internal/scanner"
)

const mockTestSSLScript = `#!/bin/bash
JSONFILE=""
TARGETS_FILE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --jsonfile) JSONFILE="$2"; shift 2;;
        --file) TARGETS_FILE="$2"; shift 2;;
        *) shift;;
    esac
done
{
printf '['
FIRST=true
while IFS= read -r target; do
    if [[ "$target" =~ ^\[(.*)\]:(.*)$ ]]; then
        ip="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
    else
        ip="${target%:*}"
        port="${target##*:}"
    fi
    [ "$FIRST" = true ] && FIRST=false || printf ','
    printf '{"id":"TLS1_2","ip":"%s/%s","port":"%s","severity":"OK","finding":"offered (OK)"},' "$ip" "$ip" "$port"
    printf '{"id":"TLS1_3","ip":"%s/%s","port":"%s","severity":"OK","finding":"offered (OK)"},' "$ip" "$ip" "$port"
    printf '{"id":"FS","ip":"%s/%s","port":"%s","severity":"OK","finding":"offered (OK)"}' "$ip" "$ip" "$port"
    if [ -z "${MOCK_NO_MLKEM:-}" ]; then
        printf ',{"id":"FS_KEMs","ip":"%s/%s","port":"%s","severity":"OK","finding":"x25519mlkem768"}' "$ip" "$ip" "$port"
    fi
done < "$TARGETS_FILE"
printf ']'
} > "$JSONFILE"
`

func installMockTestSSL(t *testing.T) {
	t.Helper()
	mockDir := t.TempDir()
	mockPath := filepath.Join(mockDir, "testssl.sh")
	if err := os.WriteFile(mockPath, []byte(mockTestSSLScript), 0755); err != nil {
		t.Fatalf("failed to write mock testssl.sh: %v", err)
	}
	t.Setenv("PATH", mockDir+":"+os.Getenv("PATH"))
}

func readJSONResults(t *testing.T, dir, file string) scanner.ScanResults {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatalf("failed to read %s: %v", file, err)
	}
	var results scanner.ScanResults
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	return results
}

func TestTargetsPath(t *testing.T) {
	installMockTestSSL(t)
	outDir := t.TempDir()

	code := run([]string{
		"--targets", "10.0.0.1:443,10.0.0.2:8443",
		"--json-file", "results.json",
		"--artifact-dir", outDir,
		"-j", "2",
	})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	results := readJSONResults(t, outDir, "results.json")

	if results.ScannedIPs != 2 {
		t.Errorf("expected 2 scanned IPs, got %d", results.ScannedIPs)
	}

	ips := map[string]bool{}
	for _, ir := range results.IPResults {
		ips[ir.IP] = true
		if len(ir.PortResults) == 0 {
			t.Errorf("IP %s has no port results", ir.IP)
			continue
		}
		pr := ir.PortResults[0]
		if pr.Status != scanner.StatusOK {
			t.Errorf("IP %s: expected status OK, got %s", ir.IP, pr.Status)
		}
		if len(pr.TlsVersions) == 0 {
			t.Errorf("IP %s: expected TLS versions", ir.IP)
		}
	}

	if !ips["10.0.0.1"] {
		t.Error("missing result for 10.0.0.1")
	}
	if !ips["10.0.0.2"] {
		t.Error("missing result for 10.0.0.2")
	}
}

func TestSingleHostPath(t *testing.T) {
	installMockTestSSL(t)
	outDir := t.TempDir()

	code := run([]string{
		"--host", "192.168.1.1",
		"--port", "8443",
		"--json-file", "results.json",
		"--artifact-dir", outDir,
		"-j", "1",
	})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	results := readJSONResults(t, outDir, "results.json")

	if results.ScannedIPs != 1 {
		t.Errorf("expected 1 scanned IP, got %d", results.ScannedIPs)
	}
	if len(results.IPResults) == 0 {
		t.Fatal("no IP results")
	}

	ir := results.IPResults[0]
	if ir.IP != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", ir.IP)
	}

	pr := ir.PortResults[0]
	if pr.Port != 8443 {
		t.Errorf("expected port 8443, got %d", pr.Port)
	}
}

func TestTargetsPathIPv6(t *testing.T) {
	installMockTestSSL(t)
	outDir := t.TempDir()
	target := "[fd2e:6f44:5dd8:c956::16]:6385"

	code := run([]string{
		"--targets", target,
		"--json-file", "results.json",
		"--artifact-dir", outDir,
		"-j", "1",
	})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	results := readJSONResults(t, outDir, "results.json")
	if results.ScannedIPs != 1 {
		t.Fatalf("expected 1 scanned IP, got %d", results.ScannedIPs)
	}
	if len(results.IPResults) == 0 {
		t.Fatal("no IP results")
	}
	if results.IPResults[0].IP != "fd2e:6f44:5dd8:c956::16" {
		t.Fatalf("expected IPv6 result, got %s", results.IPResults[0].IP)
	}
}

func TestSingleHostPathIPv6(t *testing.T) {
	installMockTestSSL(t)
	outDir := t.TempDir()

	code := run([]string{
		"--host", "fd2e:6f44:5dd8:c956::16",
		"--port", "6385",
		"--json-file", "results.json",
		"--artifact-dir", outDir,
		"-j", "1",
	})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	results := readJSONResults(t, outDir, "results.json")
	if results.ScannedIPs != 1 {
		t.Fatalf("expected 1 scanned IP, got %d", results.ScannedIPs)
	}
	if len(results.IPResults) == 0 {
		t.Fatal("no IP results")
	}
	if results.IPResults[0].IP != "fd2e:6f44:5dd8:c956::16" {
		t.Fatalf("expected IPv6 result, got %s", results.IPResults[0].IP)
	}
}

func TestPQCCheckTargets(t *testing.T) {
	installMockTestSSL(t)
	outDir := t.TempDir()

	code := run([]string{
		"--pqc-check",
		"--targets", "10.0.0.1:443",
		"--json-file", "results.json",
		"--artifact-dir", outDir,
		"-j", "1",
	})
	if code != 0 {
		t.Fatalf("expected exit 0 (PQC pass), got %d", code)
	}

	results := readJSONResults(t, outDir, "results.json")
	pr := results.IPResults[0].PortResults[0]

	if !pr.TLS13Supported {
		t.Error("expected TLS13Supported=true")
	}
	if !pr.MLKEMSupported {
		t.Error("expected MLKEMSupported=true")
	}
	if len(pr.MLKEMCiphers) == 0 {
		t.Error("expected MLKEMCiphers to be populated")
	}
}

func TestPQCComplianceFailure(t *testing.T) {
	installMockTestSSL(t)
	t.Setenv("MOCK_NO_MLKEM", "1")
	outDir := t.TempDir()

	code := run([]string{
		"--pqc-check",
		"--targets", "10.0.0.1:443",
		"--json-file", "results.json",
		"--artifact-dir", outDir,
		"-j", "1",
	})
	if code != 1 {
		t.Fatalf("expected exit 1 (PQC fail), got %d", code)
	}

	results := readJSONResults(t, outDir, "results.json")
	pr := results.IPResults[0].PortResults[0]

	if !pr.TLS13Supported {
		t.Error("expected TLS13Supported=true (TLS 1.3 is still offered)")
	}
	if pr.MLKEMSupported {
		t.Error("expected MLKEMSupported=false (mock omits MLKEM)")
	}
}

func TestInvalidTargetsFormat(t *testing.T) {
	installMockTestSSL(t)

	code := run([]string{"--targets", "not-a-valid-target"})
	if code != 1 {
		t.Errorf("expected exit 1 for all-invalid targets, got %d", code)
	}
}

func TestTargetsAllInvalid(t *testing.T) {
	installMockTestSSL(t)

	code := run([]string{"--targets", "bad-format,also-bad"})
	if code != 1 {
		t.Errorf("expected exit 1 when all targets are invalid format, got %d", code)
	}
}

func TestAllPodsWithoutCluster(t *testing.T) {
	installMockTestSSL(t)
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig")

	code := run([]string{"--all-pods"})
	if code != 1 {
		t.Errorf("expected exit 1 (no cluster), got %d", code)
	}
}

func TestVersionFlag(t *testing.T) {
	code := run([]string{"--version"})
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
}

func TestInvalidFlags(t *testing.T) {
	code := run([]string{"--nonexistent-flag"})
	if code != 2 {
		t.Errorf("expected exit 2 for bad flags, got %d", code)
	}
}
