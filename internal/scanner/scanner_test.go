package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openshift/tls-scanner/internal/k8s"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const mockTestSSLScript = `#!/bin/bash
JSONFILE=""
TARGETS_FILE=""
CIPHER_PER_PROTO=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --jsonfile) JSONFILE="$2"; shift 2;;
        --file) TARGETS_FILE="$2"; shift 2;;
        -E) CIPHER_PER_PROTO=true; shift;;
        *) shift;;
    esac
done
{
printf '['
FIRST=true
while IFS= read -r target; do
    ip="${target%%:*}"
    port="${target##*:}"
    [ "$FIRST" = true ] && FIRST=false || printf ','
    printf '{"id":"TLS1_2","ip":"%s/%s","port":"%s","severity":"OK","finding":"offered (OK)"},' "$ip" "$ip" "$port"
    printf '{"id":"TLS1_3","ip":"%s/%s","port":"%s","severity":"OK","finding":"offered (OK)"},' "$ip" "$ip" "$port"
    printf '{"id":"FS","ip":"%s/%s","port":"%s","severity":"OK","finding":"offered (OK)"},' "$ip" "$ip" "$port"
    printf '{"id":"FS_KEMs","ip":"%s/%s","port":"%s","severity":"OK","finding":"x25519mlkem768"}' "$ip" "$ip" "$port"
    if [ "$CIPHER_PER_PROTO" = true ]; then
        printf ',{"id":"cipher-tls1_2-x0033","ip":"%s/%s","port":"%s","severity":"OK","finding":"TLS_RSA_WITH_AES_128_CBC_SHA RSA AES 128"}' "$ip" "$ip" "$port"
        printf ',{"id":"cipher-tls1_2-xc02f","ip":"%s/%s","port":"%s","severity":"OK","finding":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ECDH AESGCM 128"}' "$ip" "$ip" "$port"
        printf ',{"id":"cipher-tls1_3-x1301","ip":"%s/%s","port":"%s","severity":"OK","finding":"TLS_AES_128_GCM_SHA256 ECDH AESGCM 128"}' "$ip" "$ip" "$port"
        printf ',{"id":"cipher-tls1_3-x1302","ip":"%s/%s","port":"%s","severity":"OK","finding":"TLS_AES_256_GCM_SHA384 ECDH AESGCM 256"}' "$ip" "$ip" "$port"
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

func makePod(name, namespace, ip string, ports ...int32) k8s.PodInfo {
	var containerPorts []v1.ContainerPort
	for _, p := range ports {
		containerPorts = append(containerPorts, v1.ContainerPort{ContainerPort: p, Protocol: v1.ProtocolTCP})
	}
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{Name: "main", Ports: containerPorts}},
		},
	}
	return k8s.PodInfo{
		Name: name, Namespace: namespace, IPs: []string{ip},
		Containers: []string{"main"}, Pod: pod,
	}
}

func TestScanWithMockTestSSL(t *testing.T) {
	installMockTestSSL(t)

	jobs := []ScanJob{
		{IP: "10.0.0.1", Port: 443},
		{IP: "10.0.0.2", Port: 8443},
	}
	results := Scan(jobs, 2, nil, nil, false)

	if results.ScannedIPs != 2 {
		t.Fatalf("expected 2 scanned IPs, got %d", results.ScannedIPs)
	}

	for _, ir := range results.IPResults {
		if len(ir.PortResults) == 0 {
			t.Fatalf("IP %s: no port results", ir.IP)
		}
		pr := ir.PortResults[0]
		if pr.Status != StatusOK {
			t.Errorf("IP %s: expected OK, got %s (%s)", ir.IP, pr.Status, pr.Reason)
		}
		if len(pr.TlsVersions) == 0 {
			t.Errorf("IP %s: expected TLS versions", ir.IP)
		}
	}
}

func TestScanPQCEnrichment(t *testing.T) {
	installMockTestSSL(t)

	jobs := []ScanJob{{IP: "10.0.0.1", Port: 443}}
	results := Scan(jobs, 1, nil, nil, false)

	pr := results.IPResults[0].PortResults[0]

	if !pr.TLS13Supported {
		t.Error("expected TLS13Supported=true")
	}
	if !pr.MLKEMSupported {
		t.Error("expected MLKEMSupported=true")
	}
	if len(pr.MLKEMCiphers) == 0 {
		t.Error("expected MLKEMCiphers populated")
	}
	found := false
	for _, k := range pr.MLKEMCiphers {
		if k == "x25519mlkem768" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected x25519mlkem768 in MLKEMCiphers, got %v", pr.MLKEMCiphers)
	}
}

func TestPerformClusterScanWithMockPods(t *testing.T) {
	installMockTestSSL(t)

	pods := []k8s.PodInfo{
		makePod("apiserver-1", "openshift-apiserver", "10.128.0.10", 8443),
		makePod("etcd-1", "openshift-etcd", "10.128.0.20", 2379, 2380),
		makePod("no-ports", "openshift-console", "10.128.0.30"),
	}

	results := PerformClusterScan(pods, 2, nil, false)

	if results.ScannedIPs != 3 {
		t.Errorf("expected 3 scanned IPs (including no-ports), got %d", results.ScannedIPs)
	}

	portsByIP := map[string][]PortResult{}
	for _, ir := range results.IPResults {
		portsByIP[ir.IP] = ir.PortResults
	}

	if prs, ok := portsByIP["10.128.0.10"]; ok {
		if len(prs) != 1 || prs[0].Port != 8443 {
			t.Errorf("apiserver: expected port 8443, got %v", prs)
		}
		if prs[0].Status != StatusOK {
			t.Errorf("apiserver: expected OK, got %s", prs[0].Status)
		}
	} else {
		t.Error("missing results for apiserver 10.128.0.10")
	}

	if prs, ok := portsByIP["10.128.0.20"]; ok {
		if len(prs) != 2 {
			t.Errorf("etcd: expected 2 port results, got %d", len(prs))
		}
	} else {
		t.Error("missing results for etcd 10.128.0.20")
	}

	if prs, ok := portsByIP["10.128.0.30"]; ok {
		if len(prs) != 1 || prs[0].Status != StatusNoPorts {
			t.Errorf("no-ports pod: expected StatusNoPorts, got %v", prs)
		}
	} else {
		t.Error("missing results for no-ports pod 10.128.0.30")
	}
}

func TestAssembleResults(t *testing.T) {
	batch1 := []portScanResult{
		{ip: "10.0.0.1", result: PortResult{Port: 443, Status: StatusOK}},
		{ip: "10.0.0.1", result: PortResult{Port: 8443, Status: StatusOK}},
	}
	batch2 := []portScanResult{
		{ip: "10.0.0.2", result: PortResult{Port: 443, Status: StatusNoTLS}},
	}

	results := assembleResults(time.Now(), 0, nil, batch1, batch2)

	if results.ScannedIPs != 2 {
		t.Errorf("expected 2 scanned IPs, got %d", results.ScannedIPs)
	}

	portsByIP := map[string]int{}
	for _, ir := range results.IPResults {
		portsByIP[ir.IP] = len(ir.PortResults)
	}
	if portsByIP["10.0.0.1"] != 2 {
		t.Errorf("expected 2 port results for 10.0.0.1, got %d", portsByIP["10.0.0.1"])
	}
	if portsByIP["10.0.0.2"] != 1 {
		t.Errorf("expected 1 port result for 10.0.0.2, got %d", portsByIP["10.0.0.2"])
	}
}
