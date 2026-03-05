package main

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStringInSlice(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		list     []string
		expected bool
	}{
		{"found", "a", []string{"a", "b", "c"}, true},
		{"not found", "d", []string{"a", "b", "c"}, false},
		{"empty list", "a", []string{}, false},
		{"empty string found", "", []string{"", "a"}, true},
		{"empty string not found", "", []string{"a", "b"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stringInSlice(tt.s, tt.list)
			if got != tt.expected {
				t.Errorf("stringInSlice(%q, %v) = %v, want %v", tt.s, tt.list, got, tt.expected)
			}
		})
	}
}

func TestGetMinVersionValue(t *testing.T) {
	tests := []struct {
		name     string
		versions []string
		expected int
	}{
		{"empty", []string{}, 0},
		{"single TLS 1.2", []string{"TLSv1.2"}, 12},
		{"single TLS 1.3", []string{"TLSv1.3"}, 13},
		{"mixed versions picks lowest", []string{"TLSv1.2", "TLSv1.3"}, 12},
		{"all versions picks lowest", []string{"TLSv1.3", "TLSv1.1", "TLSv1.2"}, 11},
		{"TLS 1.0 is lowest", []string{"TLSv1.0", "TLSv1.2"}, 10},
		{"VersionTLS format", []string{"VersionTLS12", "VersionTLS13"}, 12},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getMinVersionValue(tt.versions)
			if got != tt.expected {
				t.Errorf("getMinVersionValue(%v) = %d, want %d", tt.versions, got, tt.expected)
			}
		})
	}
}

func TestCheckCipherCompliance(t *testing.T) {
	tests := []struct {
		name     string
		got      []string
		expected []string
		want     bool
	}{
		{
			"all ciphers match",
			[]string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			[]string{"TLS_AES_128_GCM_SHA256"},
			true,
		},
		{
			"cipher not in expected set",
			[]string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "UNKNOWN_CIPHER"},
			[]string{"TLS_AES_128_GCM_SHA256"},
			false,
		},
		{
			"empty got with non-empty expected",
			[]string{},
			[]string{"TLS_AES_128_GCM_SHA256"},
			false,
		},
		{
			"both empty",
			[]string{},
			[]string{},
			true,
		},
		{
			"multiple matching ciphers",
			[]string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			[]string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkCipherCompliance(tt.got, tt.expected)
			if got != tt.want {
				t.Errorf("checkCipherCompliance(%v, %v) = %v, want %v", tt.got, tt.expected, got, tt.want)
			}
		})
	}
}

func TestCheckCompliance(t *testing.T) {
	t.Run("ingress version compliance passes when port TLS >= configured min", func(t *testing.T) {
		portResult := &PortResult{
			TlsVersions: []string{"TLSv1.2", "TLSv1.3"},
			TlsCiphers:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		}
		profile := &TLSSecurityProfile{
			IngressController: &IngressTLSProfile{
				MinTLSVersion: "TLSv1.2",
				Ciphers:       []string{"TLS_AES_128_GCM_SHA256"},
			},
			APIServer:     &APIServerTLSProfile{},
			KubeletConfig: &KubeletTLSProfile{},
		}
		checkCompliance(portResult, profile)
		if !portResult.IngressTLSConfigCompliance.Version {
			t.Error("expected ingress version compliance to pass")
		}
		if !portResult.IngressTLSConfigCompliance.Ciphers {
			t.Error("expected ingress cipher compliance to pass")
		}
	})

	t.Run("ingress version compliance fails when port TLS < configured min", func(t *testing.T) {
		portResult := &PortResult{
			TlsVersions: []string{"TLSv1.0", "TLSv1.1"},
			TlsCiphers:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		}
		profile := &TLSSecurityProfile{
			IngressController: &IngressTLSProfile{
				MinTLSVersion: "TLSv1.2",
				Ciphers:       []string{"TLS_AES_128_GCM_SHA256"},
			},
			APIServer:     &APIServerTLSProfile{},
			KubeletConfig: &KubeletTLSProfile{},
		}
		checkCompliance(portResult, profile)
		if portResult.IngressTLSConfigCompliance.Version {
			t.Error("expected ingress version compliance to fail")
		}
	})

	t.Run("api server compliance check", func(t *testing.T) {
		portResult := &PortResult{
			TlsVersions: []string{"TLSv1.3"},
			TlsCiphers:  []string{"TLS_AKE_WITH_AES_256_GCM_SHA384"},
		}
		profile := &TLSSecurityProfile{
			IngressController: &IngressTLSProfile{},
			APIServer: &APIServerTLSProfile{
				MinTLSVersion: "TLSv1.2",
				Ciphers:       []string{"TLS_AES_256_GCM_SHA384"},
			},
			KubeletConfig: &KubeletTLSProfile{},
		}
		checkCompliance(portResult, profile)
		if !portResult.APIServerTLSConfigCompliance.Version {
			t.Error("expected API server version compliance to pass")
		}
		if !portResult.APIServerTLSConfigCompliance.Ciphers {
			t.Error("expected API server cipher compliance to pass")
		}
	})

	t.Run("kubelet compliance check", func(t *testing.T) {
		portResult := &PortResult{
			TlsVersions: []string{"TLSv1.2"},
			TlsCiphers:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		}
		profile := &TLSSecurityProfile{
			IngressController: &IngressTLSProfile{},
			APIServer:         &APIServerTLSProfile{},
			KubeletConfig: &KubeletTLSProfile{
				MinTLSVersion:   "TLSv1.2",
				TLSCipherSuites: []string{"TLS_AES_128_GCM_SHA256"},
			},
		}
		checkCompliance(portResult, profile)
		if !portResult.KubeletTLSConfigCompliance.Version {
			t.Error("expected kubelet version compliance to pass")
		}
		if !portResult.KubeletTLSConfigCompliance.Ciphers {
			t.Error("expected kubelet cipher compliance to pass")
		}
	})
}

func TestHasComplianceFailures(t *testing.T) {
	tests := []struct {
		name    string
		results ScanResults
		want    bool
	}{
		{
			"no failures when all compliant",
			ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{
						IngressTLSConfigCompliance:   &TLSConfigComplianceResult{Version: true, Ciphers: true},
						APIServerTLSConfigCompliance: &TLSConfigComplianceResult{Version: true, Ciphers: true},
						KubeletTLSConfigCompliance:   &TLSConfigComplianceResult{Version: true, Ciphers: true},
					}},
				}},
			},
			false,
		},
		{
			"failure when ingress version non-compliant",
			ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{
						IngressTLSConfigCompliance: &TLSConfigComplianceResult{Version: false, Ciphers: true},
					}},
				}},
			},
			true,
		},
		{
			"failure when api server ciphers non-compliant",
			ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{
						APIServerTLSConfigCompliance: &TLSConfigComplianceResult{Version: true, Ciphers: false},
					}},
				}},
			},
			true,
		},
		{
			"failure when kubelet non-compliant",
			ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{
						KubeletTLSConfigCompliance: &TLSConfigComplianceResult{Version: false, Ciphers: false},
					}},
				}},
			},
			true,
		},
		{
			"no failures with nil compliance results",
			ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{Port: 443}},
				}},
			},
			false,
		},
		{
			"no failures with empty results",
			ScanResults{},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasComplianceFailures(tt.results)
			if got != tt.want {
				t.Errorf("hasComplianceFailures() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasPQCComplianceFailures(t *testing.T) {
	tests := []struct {
		name    string
		results ScanResults
		want    bool
	}{
		{
			"passes when TLS 1.3 and ML-KEM supported",
			ScanResults{
				IPResults: []IPResult{{
					IP: "10.0.0.1",
					PortResults: []PortResult{{
						Port:           443,
						Status:         StatusOK,
						TLS13Supported: true,
						MLKEMSupported: true,
						MLKEMCiphers:   []string{"x25519mlkem768"},
					}},
				}},
			},
			false,
		},
		{
			"fails when TLS 1.3 not supported",
			ScanResults{
				IPResults: []IPResult{{
					IP: "10.0.0.1",
					PortResults: []PortResult{{
						Port:           443,
						Status:         StatusOK,
						TLS13Supported: false,
					}},
				}},
			},
			true,
		},
		{
			"fails when ML-KEM not supported",
			ScanResults{
				IPResults: []IPResult{{
					IP: "10.0.0.1",
					PortResults: []PortResult{{
						Port:           443,
						Status:         StatusOK,
						TLS13Supported: true,
						MLKEMSupported: false,
					}},
				}},
			},
			true,
		},
		{
			"skips NO_PORTS status",
			ScanResults{
				IPResults: []IPResult{{
					IP: "10.0.0.1",
					PortResults: []PortResult{{
						Status: StatusNoPorts,
					}},
				}},
			},
			false,
		},
		{
			"fails when ML-KEM ciphers have no valid KEM",
			ScanResults{
				IPResults: []IPResult{{
					IP: "10.0.0.1",
					PortResults: []PortResult{{
						Port:           443,
						Status:         StatusOK,
						TLS13Supported: true,
						MLKEMSupported: true,
						MLKEMCiphers:   []string{"some_unknown_kem"},
					}},
				}},
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasPQCComplianceFailures(tt.results)
			if got != tt.want {
				t.Errorf("hasPQCComplianceFailures() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractTLSInfo(t *testing.T) {
	t.Run("extracts versions and ciphers from ssl-enum-ciphers script", func(t *testing.T) {
		scanRun := ScanRun{
			Hosts: []Host{{
				Ports: []Port{{
					Scripts: []Script{{
						ID: "ssl-enum-ciphers",
						Tables: []Table{
							{
								Key: "TLSv1.2",
								Tables: []Table{{
									Key: "ciphers",
									Tables: []Table{{
										Elems: []Elem{
											{Key: "name", Value: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
											{Key: "strength", Value: "A"},
										},
									}},
								}},
							},
							{
								Key: "TLSv1.3",
								Tables: []Table{{
									Key: "ciphers",
									Tables: []Table{{
										Elems: []Elem{
											{Key: "name", Value: "TLS_AKE_WITH_AES_256_GCM_SHA384"},
											{Key: "strength", Value: "A"},
										},
									}},
								}},
							},
						},
					}},
				}},
			}},
		}

		versions, ciphers, strength := extractTLSInfo(scanRun)

		if len(versions) != 2 {
			t.Fatalf("expected 2 TLS versions, got %d: %v", len(versions), versions)
		}
		if !stringInSlice("TLSv1.2", versions) || !stringInSlice("TLSv1.3", versions) {
			t.Errorf("expected TLSv1.2 and TLSv1.3, got %v", versions)
		}
		if len(ciphers) != 2 {
			t.Fatalf("expected 2 ciphers, got %d: %v", len(ciphers), ciphers)
		}
		if strength["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] != "A" {
			t.Errorf("expected cipher strength A, got %s", strength["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"])
		}
	})

	t.Run("returns empty for no hosts", func(t *testing.T) {
		scanRun := ScanRun{}
		versions, ciphers, _ := extractTLSInfo(scanRun)
		if len(versions) != 0 || len(ciphers) != 0 {
			t.Errorf("expected empty results, got versions=%v, ciphers=%v", versions, ciphers)
		}
	})

	t.Run("deduplicates versions and ciphers", func(t *testing.T) {
		scanRun := ScanRun{
			Hosts: []Host{
				{Ports: []Port{{
					Scripts: []Script{{
						ID: "ssl-enum-ciphers",
						Tables: []Table{{
							Key: "TLSv1.2",
							Tables: []Table{{
								Key: "ciphers",
								Tables: []Table{{
									Elems: []Elem{
										{Key: "name", Value: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
										{Key: "strength", Value: "A"},
									},
								}},
							}},
						}},
					}},
				}}},
				{Ports: []Port{{
					Scripts: []Script{{
						ID: "ssl-enum-ciphers",
						Tables: []Table{{
							Key: "TLSv1.2",
							Tables: []Table{{
								Key: "ciphers",
								Tables: []Table{{
									Elems: []Elem{
										{Key: "name", Value: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
										{Key: "strength", Value: "A"},
									},
								}},
							}},
						}},
					}},
				}}},
			},
		}

		versions, ciphers, _ := extractTLSInfo(scanRun)
		if len(versions) != 1 {
			t.Errorf("expected 1 deduplicated version, got %d: %v", len(versions), versions)
		}
		if len(ciphers) != 1 {
			t.Errorf("expected 1 deduplicated cipher, got %d: %v", len(ciphers), ciphers)
		}
	})
}

func TestParseTestSSLOutput(t *testing.T) {
	t.Run("parses protocol and cipher findings", func(t *testing.T) {
		jsonData := `[
			{"id": "TLS1_2", "finding": "offered", "severity": "OK", "ip": "10.0.0.1", "port": "443"},
			{"id": "TLS1_3", "finding": "offered", "severity": "OK", "ip": "10.0.0.1", "port": "443"},
			{"id": "cipher-tls1_2_xc02f", "finding": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "severity": "OK", "ip": "10.0.0.1", "port": "443"},
			{"id": "cipher-tls1_3_x1301", "finding": "TLS_AES_128_GCM_SHA256", "severity": "OK", "ip": "10.0.0.1", "port": "443"}
		]`

		scanRun := parseTestSSLOutput([]byte(jsonData), "10.0.0.1", "443")

		if len(scanRun.Hosts) != 1 {
			t.Fatalf("expected 1 host, got %d", len(scanRun.Hosts))
		}
		if len(scanRun.Hosts[0].Ports) != 1 {
			t.Fatalf("expected 1 port, got %d", len(scanRun.Hosts[0].Ports))
		}

		versions, ciphers, _ := extractTLSInfo(scanRun)
		if !stringInSlice("TLSv1.2", versions) {
			t.Errorf("expected TLSv1.2 in versions, got %v", versions)
		}
		if !stringInSlice("TLSv1.3", versions) {
			t.Errorf("expected TLSv1.3 in versions, got %v", versions)
		}
		if len(ciphers) != 2 {
			t.Errorf("expected 2 ciphers, got %d: %v", len(ciphers), ciphers)
		}
	})

	t.Run("handles invalid JSON gracefully", func(t *testing.T) {
		scanRun := parseTestSSLOutput([]byte("not json"), "10.0.0.1", "443")
		if len(scanRun.Hosts) != 1 {
			t.Fatal("expected fallback host")
		}
		if scanRun.Hosts[0].Ports[0].PortID != "443" {
			t.Errorf("expected port 443 in fallback, got %s", scanRun.Hosts[0].Ports[0].PortID)
		}
	})

	t.Run("ignores not offered protocols", func(t *testing.T) {
		jsonData := `[
			{"id": "TLS1_2", "finding": "offered", "severity": "OK"},
			{"id": "TLS1_1", "finding": "not offered", "severity": "OK"},
			{"id": "SSLv3", "finding": "not offered", "severity": "OK"}
		]`
		scanRun := parseTestSSLOutput([]byte(jsonData), "10.0.0.1", "443")
		versions, _, _ := extractTLSInfo(scanRun)
		if len(versions) != 1 || versions[0] != "TLSv1.2" {
			t.Errorf("expected only TLSv1.2, got %v", versions)
		}
	})

	t.Run("ignores cipher metadata entries", func(t *testing.T) {
		jsonData := `[
			{"id": "cipher_order-tls1_2", "finding": "server", "severity": "OK"},
			{"id": "cipherlist_NULL", "finding": "not offered", "severity": "OK"},
			{"id": "cipher_strength_score", "finding": "90", "severity": "OK"},
			{"id": "cipher-tls1_2_x0001", "finding": "TLS_RSA_WITH_AES_128_GCM_SHA256", "severity": "OK"}
		]`
		scanRun := parseTestSSLOutput([]byte(jsonData), "10.0.0.1", "443")
		_, ciphers, _ := extractTLSInfo(scanRun)
		if len(ciphers) != 1 {
			t.Errorf("expected 1 cipher (metadata excluded), got %d: %v", len(ciphers), ciphers)
		}
	})
}

func TestConvertTestSSLToScanRun(t *testing.T) {
	rawData := []map[string]interface{}{
		{"id": "TLS1_2", "finding": "offered", "severity": "OK"},
		{"id": "cipher-tls1_2_xc02f", "finding": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "severity": "OK"},
	}

	scanRun := convertTestSSLToScanRun(rawData, "10.0.0.1", "443")

	if scanRun.Hosts[0].Status.State != "up" {
		t.Errorf("expected host state 'up', got %q", scanRun.Hosts[0].Status.State)
	}
	if scanRun.Hosts[0].Ports[0].PortID != "443" {
		t.Errorf("expected port 443, got %s", scanRun.Hosts[0].Ports[0].PortID)
	}
	if scanRun.Hosts[0].Ports[0].Service.Name != "ssl/tls" {
		t.Errorf("expected service ssl/tls, got %s", scanRun.Hosts[0].Ports[0].Service.Name)
	}
}

func TestGroupTestSSLOutputByPort(t *testing.T) {
	jsonData := `[
		{"id": "TLS1_2", "finding": "offered", "port": "443", "ip": "10.0.0.1"},
		{"id": "TLS1_3", "finding": "offered", "port": "443", "ip": "10.0.0.1"},
		{"id": "TLS1_2", "finding": "offered", "port": "8443", "ip": "10.0.0.1"}
	]`

	grouped, err := groupTestSSLOutputByPort([]byte(jsonData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(grouped) != 2 {
		t.Fatalf("expected 2 port groups, got %d", len(grouped))
	}
	if _, ok := grouped["443"]; !ok {
		t.Error("expected port 443 in grouped output")
	}
	if _, ok := grouped["8443"]; !ok {
		t.Error("expected port 8443 in grouped output")
	}
}

func TestGroupTestSSLOutputByIPPort(t *testing.T) {
	jsonData := `[
		{"id": "TLS1_2", "finding": "offered", "port": "443", "ip": "10.0.0.1"},
		{"id": "TLS1_2", "finding": "offered", "port": "443", "ip": "10.0.0.2"},
		{"id": "TLS1_3", "finding": "offered", "port": "8443", "ip": "10.0.0.1"}
	]`

	grouped, err := groupTestSSLOutputByIPPort([]byte(jsonData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(grouped) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(grouped))
	}
	if _, ok := grouped["10.0.0.1:443"]; !ok {
		t.Error("expected 10.0.0.1:443 in grouped output")
	}
	if _, ok := grouped["10.0.0.2:443"]; !ok {
		t.Error("expected 10.0.0.2:443 in grouped output")
	}
	if _, ok := grouped["10.0.0.1:8443"]; !ok {
		t.Error("expected 10.0.0.1:8443 in grouped output")
	}
}

func TestExtractTLSVersion(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"TLS1_3", "TLSv1.3"},
		{"TLS1_2", "TLSv1.2"},
		{"TLS1_1", "TLSv1.1"},
		{"tls1", "TLSv1.0"},
		{"SSLv3", "SSLv3"},
		{"SSLv2", "SSLv2"},
		{"ssl3", "SSLv3"},
		{"unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := extractTLSVersion(tt.id)
			if got != tt.want {
				t.Errorf("extractTLSVersion(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

func TestExtractTLSVersionFromCipherID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		finding map[string]interface{}
		want    string
	}{
		{"tls1_3 in id", "cipher-tls1_3_x1301", nil, "TLSv1.3"},
		{"tls1_2 in id", "cipher-tls1_2_xc02f", nil, "TLSv1.2"},
		{"tls1_1 in id", "cipher-tls1_1_x0001", nil, "TLSv1.1"},
		{"ssl3 in id", "cipher-ssl3_x0001", nil, "SSLv3"},
		{"TLS 1.3 cipher name implies 1.3", "cipher-x0001", map[string]interface{}{"finding": "TLS_AES_128_GCM_SHA256"}, "TLSv1.3"},
		{"fallback to TLSv1.2", "cipher-x0001", map[string]interface{}{"finding": "something_else"}, "TLSv1.2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := tt.finding
			if finding == nil {
				finding = map[string]interface{}{}
			}
			got := extractTLSVersionFromCipherID(tt.id, finding)
			if got != tt.want {
				t.Errorf("extractTLSVersionFromCipherID(%q, ...) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

func TestIsProtocolID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"TLS1_2", true},
		{"tls1_3", true},
		{"SSLv3", true},
		{"ssl2", true},
		{"cipher-tls1_2", false},
		{"FS_KEMs", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := isProtocolID(tt.id); got != tt.want {
				t.Errorf("isProtocolID(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

func TestExtractCipherName(t *testing.T) {
	tests := []struct {
		finding string
		want    string
	}{
		{"TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256"},
		{"ECDHE-RSA-AES128-GCM-SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.finding, func(t *testing.T) {
			got := extractCipherName(tt.finding)
			if got != tt.want {
				t.Errorf("extractCipherName(%q) = %q, want %q", tt.finding, got, tt.want)
			}
		})
	}
}

func TestMapSeverityToStrength(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"OK", "A"},
		{"LOW", "A"},
		{"MEDIUM", "B"},
		{"HIGH", "C"},
		{"CRITICAL", "F"},
		{"UNKNOWN", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := mapSeverityToStrength(tt.severity)
			if got != tt.want {
				t.Errorf("mapSeverityToStrength(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestIsKEMGroup(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"x25519mlkem768", true},
		{"X25519MLKEM768", true},
		{"ML-KEM-768", true},
		{"kyber768", true},
		{"sntrup761", true},
		{"x25519", false},
		{"secp256r1", false},
		{"secp384r1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isKEMGroup(tt.name); got != tt.want {
				t.Errorf("isKEMGroup(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestParsePQCFindings(t *testing.T) {
	t.Run("detects TLS 1.3 and ML-KEM", func(t *testing.T) {
		findings := []map[string]interface{}{
			{"id": "TLS1_3", "finding": "offered"},
			{"id": "TLS1_2", "finding": "offered"},
			{"id": "FS_KEMs", "finding": "x25519mlkem768 mlkem768"},
		}

		tls13, versions, mlkem, mlkemKEMs, allKEMs := parsePQCFindings(findings)

		if !tls13 {
			t.Error("expected TLS 1.3 to be detected")
		}
		if len(versions) != 2 {
			t.Errorf("expected 2 versions, got %d: %v", len(versions), versions)
		}
		if !mlkem {
			t.Error("expected ML-KEM to be detected")
		}
		if len(mlkemKEMs) != 2 {
			t.Errorf("expected 2 ML-KEM KEMs, got %d: %v", len(mlkemKEMs), mlkemKEMs)
		}
		if len(allKEMs) != 2 {
			t.Errorf("expected 2 all KEMs, got %d: %v", len(allKEMs), allKEMs)
		}
	})

	t.Run("detects from supported_groups", func(t *testing.T) {
		findings := []map[string]interface{}{
			{"id": "TLS1_3", "finding": "offered"},
			{"id": "supported_groups", "finding": "x25519 secp256r1 X25519MLKEM768"},
		}

		tls13, _, mlkem, mlkemKEMs, allKEMs := parsePQCFindings(findings)

		if !tls13 {
			t.Error("expected TLS 1.3")
		}
		if !mlkem {
			t.Error("expected ML-KEM from supported_groups")
		}
		if !stringInSlice("X25519MLKEM768", mlkemKEMs) {
			t.Errorf("expected X25519MLKEM768 in mlkemKEMs, got %v", mlkemKEMs)
		}
		if len(allKEMs) != 3 {
			t.Errorf("expected 3 all KEMs, got %d: %v", len(allKEMs), allKEMs)
		}
	})

	t.Run("no TLS 1.3 when not offered", func(t *testing.T) {
		findings := []map[string]interface{}{
			{"id": "TLS1_2", "finding": "offered"},
			{"id": "TLS1_3", "finding": "not offered"},
		}

		tls13, versions, _, _, _ := parsePQCFindings(findings)

		if tls13 {
			t.Error("expected TLS 1.3 not to be detected")
		}
		if len(versions) != 1 || versions[0] != "TLSv1.2" {
			t.Errorf("expected only TLSv1.2, got %v", versions)
		}
	})
}

func TestExtractKeyExchangeFromTestSSL(t *testing.T) {
	t.Run("extracts forward secrecy and KEMs", func(t *testing.T) {
		jsonData := `[
			{"id": "FS", "finding": "offered"},
			{"id": "FS_ECDHE", "finding": "P-256 P-384"},
			{"id": "FS_KEMs", "finding": "x25519mlkem768"},
			{"id": "supported_groups", "finding": "x25519 secp256r1 X25519MLKEM768"}
		]`

		info := extractKeyExchangeFromTestSSL([]byte(jsonData))
		if info == nil {
			t.Fatal("expected non-nil key exchange info")
		}
		if !info.ForwardSecrecy.Supported {
			t.Error("expected forward secrecy to be supported")
		}
		if len(info.ForwardSecrecy.ECDHE) != 2 {
			t.Errorf("expected 2 ECDHE groups, got %d: %v", len(info.ForwardSecrecy.ECDHE), info.ForwardSecrecy.ECDHE)
		}
		if len(info.ForwardSecrecy.KEMs) != 2 {
			t.Errorf("expected 2 KEM groups, got %d: %v", len(info.ForwardSecrecy.KEMs), info.ForwardSecrecy.KEMs)
		}
		if len(info.Groups) != 3 {
			t.Errorf("expected 3 groups, got %d: %v", len(info.Groups), info.Groups)
		}
	})

	t.Run("returns nil for empty data", func(t *testing.T) {
		info := extractKeyExchangeFromTestSSL([]byte(`[]`))
		if info != nil {
			t.Error("expected nil for empty findings")
		}
	})

	t.Run("returns nil for invalid JSON", func(t *testing.T) {
		info := extractKeyExchangeFromTestSSL([]byte("bad"))
		if info != nil {
			t.Error("expected nil for invalid JSON")
		}
	})
}

func TestCategorizePortResult(t *testing.T) {
	tests := []struct {
		name       string
		portResult PortResult
		tlsPort    Port
		wantStatus ScanStatus
	}{
		{
			"OK when ciphers detected",
			PortResult{TlsCiphers: []string{"TLS_AES_128_GCM_SHA256"}, State: "open"},
			Port{},
			StatusOK,
		},
		{
			"filtered port",
			PortResult{State: "filtered"},
			Port{},
			StatusFiltered,
		},
		{
			"closed port",
			PortResult{State: "closed"},
			Port{},
			StatusClosed,
		},
		{
			"open port no TLS",
			PortResult{State: "open"},
			Port{State: State{Reason: "syn-ack"}},
			StatusNoTLS,
		},
		{
			"timeout on no-response",
			PortResult{State: "open"},
			Port{State: State{Reason: "no-response"}},
			StatusTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStatus, _ := categorizePortResult(tt.portResult, tt.tlsPort)
			if gotStatus != tt.wantStatus {
				t.Errorf("categorizePortResult() status = %v, want %v", gotStatus, tt.wantStatus)
			}
		})
	}
}

func TestLimitPodsToIPCount(t *testing.T) {
	pods := []PodInfo{
		{Name: "pod-1", IPs: []string{"10.0.0.1", "10.0.0.2"}},
		{Name: "pod-2", IPs: []string{"10.0.0.3"}},
		{Name: "pod-3", IPs: []string{"10.0.0.4", "10.0.0.5", "10.0.0.6"}},
	}

	t.Run("zero limit returns all", func(t *testing.T) {
		result := limitPodsToIPCount(pods, 0)
		if len(result) != 3 {
			t.Errorf("expected 3 pods, got %d", len(result))
		}
	})

	t.Run("limit of 2 returns first pod only", func(t *testing.T) {
		result := limitPodsToIPCount(pods, 2)
		if len(result) != 1 {
			t.Errorf("expected 1 pod, got %d", len(result))
		}
	})

	t.Run("limit of 3 returns first two pods", func(t *testing.T) {
		result := limitPodsToIPCount(pods, 3)
		if len(result) != 2 {
			t.Errorf("expected 2 pods, got %d", len(result))
		}
	})

	t.Run("limit exceeding total returns all", func(t *testing.T) {
		result := limitPodsToIPCount(pods, 100)
		if len(result) != 3 {
			t.Errorf("expected 3 pods, got %d", len(result))
		}
	})

	t.Run("limit of 4 truncates third pod IPs", func(t *testing.T) {
		result := limitPodsToIPCount(pods, 4)
		if len(result) != 3 {
			t.Errorf("expected 3 pods, got %d", len(result))
		}
		totalIPs := 0
		for _, p := range result {
			totalIPs += len(p.IPs)
		}
		if totalIPs != 4 {
			t.Errorf("expected 4 total IPs, got %d", totalIPs)
		}
	})
}

func TestDiscoverPortsFromPodSpec(t *testing.T) {
	t.Run("discovers TCP ports from containers", func(t *testing.T) {
		pod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: v1.PodSpec{
				Containers: []v1.Container{{
					Name: "web",
					Ports: []v1.ContainerPort{
						{ContainerPort: 8443, Protocol: v1.ProtocolTCP},
						{ContainerPort: 8080, Protocol: v1.ProtocolTCP},
						{ContainerPort: 9090, Protocol: v1.ProtocolUDP},
					},
				}},
			},
		}

		ports, err := discoverPortsFromPodSpec(pod)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ports) != 2 {
			t.Fatalf("expected 2 TCP ports, got %d: %v", len(ports), ports)
		}
	})

	t.Run("includes init container ports", func(t *testing.T) {
		pod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: v1.PodSpec{
				InitContainers: []v1.Container{{
					Name:  "init",
					Ports: []v1.ContainerPort{{ContainerPort: 9443, Protocol: v1.ProtocolTCP}},
				}},
				Containers: []v1.Container{{
					Name:  "main",
					Ports: []v1.ContainerPort{{ContainerPort: 443, Protocol: v1.ProtocolTCP}},
				}},
			},
		}

		ports, err := discoverPortsFromPodSpec(pod)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ports) != 2 {
			t.Fatalf("expected 2 ports, got %d: %v", len(ports), ports)
		}
	})

	t.Run("returns empty for pod with no ports", func(t *testing.T) {
		pod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
			Spec: v1.PodSpec{
				Containers: []v1.Container{{Name: "worker"}},
			},
		}

		ports, err := discoverPortsFromPodSpec(pod)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ports) != 0 {
			t.Errorf("expected 0 ports, got %d", len(ports))
		}
	})
}

func TestFilterPodsByNamespace(t *testing.T) {
	pods := []PodInfo{
		{Name: "pod-1", Namespace: "openshift-etcd"},
		{Name: "pod-2", Namespace: "openshift-apiserver"},
		{Name: "pod-3", Namespace: "default"},
		{Name: "pod-4", Namespace: "openshift-etcd"},
	}

	t.Run("empty filter returns all", func(t *testing.T) {
		result := filterPodsByNamespace(pods, "")
		if len(result) != 4 {
			t.Errorf("expected 4 pods, got %d", len(result))
		}
	})

	t.Run("single namespace filter", func(t *testing.T) {
		result := filterPodsByNamespace(pods, "openshift-etcd")
		if len(result) != 2 {
			t.Errorf("expected 2 pods, got %d", len(result))
		}
	})

	t.Run("multiple namespace filter", func(t *testing.T) {
		result := filterPodsByNamespace(pods, "openshift-etcd,default")
		if len(result) != 3 {
			t.Errorf("expected 3 pods, got %d", len(result))
		}
	})

	t.Run("non-matching filter returns empty", func(t *testing.T) {
		result := filterPodsByNamespace(pods, "nonexistent")
		if len(result) != 0 {
			t.Errorf("expected 0 pods, got %d", len(result))
		}
	})
}
