package scanner

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/tls-scanner/internal/k8s"
)

func intermediateProfile() *k8s.TLSSecurityProfile {
	return &k8s.TLSSecurityProfile{
		APIServer: &k8s.APIServerTLSProfile{
			Type:          "Intermediate",
			MinTLSVersion: string(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion),
			Ciphers:       configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers,
		},
		IngressController: &k8s.IngressTLSProfile{
			Type:          "Intermediate",
			MinTLSVersion: string(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion),
			Ciphers:       configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers,
		},
		KubeletConfig: &k8s.KubeletTLSProfile{
			MinTLSVersion:   string(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion),
			TLSCipherSuites: configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers,
		},
	}
}

func defaultProfile() *k8s.TLSSecurityProfile {
	return &k8s.TLSSecurityProfile{
		APIServer: &k8s.APIServerTLSProfile{
			Type:          "Default",
			MinTLSVersion: string(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion),
			Ciphers:       configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers,
		},
		IngressController: &k8s.IngressTLSProfile{
			Type:          "Default",
			MinTLSVersion: string(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion),
			Ciphers:       configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers,
		},
	}
}

func modernProfile() *k8s.TLSSecurityProfile {
	return &k8s.TLSSecurityProfile{
		APIServer: &k8s.APIServerTLSProfile{
			Type:          "Modern",
			MinTLSVersion: string(configv1.TLSProfiles[configv1.TLSProfileModernType].MinTLSVersion),
			Ciphers:       configv1.TLSProfiles[configv1.TLSProfileModernType].Ciphers,
		},
		IngressController: &k8s.IngressTLSProfile{
			Type:          "Modern",
			MinTLSVersion: string(configv1.TLSProfiles[configv1.TLSProfileModernType].MinTLSVersion),
			Ciphers:       configv1.TLSProfiles[configv1.TLSProfileModernType].Ciphers,
		},
	}
}

func emptyProfile() *k8s.TLSSecurityProfile {
	return &k8s.TLSSecurityProfile{
		APIServer: &k8s.APIServerTLSProfile{
			Type: "Default",
		},
		IngressController: &k8s.IngressTLSProfile{
			Type: "Default",
		},
	}
}

func TestCheckCompliance(t *testing.T) {
	tests := []struct {
		name          string
		tlsVersions   []string
		ciphers       []string
		profile       *k8s.TLSSecurityProfile
		componentType ComponentType
		wantVersion   bool
		wantCiphers   bool
		wantProfile   string
		// which result field should be populated
		checkIngress bool
		checkAPI     bool
		checkKubelet bool
	}{
		{
			name:          "Generic component: Default profile with TLS 1.2+1.3",
			tlsVersions:   []string{"TLSv1.2", "TLSv1.3"},
			ciphers:       []string{"TLS_AKE_WITH_AES_256_GCM_SHA384", "TLS_AKE_WITH_AES_128_GCM_SHA256"},
			profile:       defaultProfile(),
			componentType: GenericComponent,
			wantVersion:   true,
			wantCiphers:   true,
			wantProfile:   "Default",
			checkAPI:      true,
		},
		{
			name:          "Generic component: empty profile = compliant",
			tlsVersions:   []string{"TLSv1.2", "TLSv1.3"},
			ciphers:       []string{"TLS_AKE_WITH_AES_256_GCM_SHA384"},
			profile:       emptyProfile(),
			componentType: GenericComponent,
			wantVersion:   true,
			wantCiphers:   true,
			wantProfile:   "Default",
			checkAPI:      true,
		},
		{
			name:          "Generic component: Modern profile with TLS 1.3 = pass",
			tlsVersions:   []string{"TLSv1.3"},
			ciphers:       []string{"TLS_AKE_WITH_AES_256_GCM_SHA384"},
			profile:       modernProfile(),
			componentType: GenericComponent,
			wantVersion:   true,
			wantCiphers:   true,
			wantProfile:   "Modern",
			checkAPI:      true,
		},
		{
			name:          "Generic component: Modern profile with TLS 1.2 = version fail",
			tlsVersions:   []string{"TLSv1.2"},
			ciphers:       []string{"TLS_AKE_WITH_AES_256_GCM_SHA384"},
			profile:       modernProfile(),
			componentType: GenericComponent,
			wantVersion:   false,
			wantCiphers:   true,
			wantProfile:   "Modern",
			checkAPI:      true,
		},
		{
			name:          "Generic component: Intermediate profile with unknown cipher = cipher fail",
			tlsVersions:   []string{"TLSv1.2", "TLSv1.3"},
			ciphers:       []string{"UNKNOWN_CIPHER_SUITE"},
			profile:       intermediateProfile(),
			componentType: GenericComponent,
			wantVersion:   true,
			wantCiphers:   false,
			wantProfile:   "Intermediate",
			checkAPI:      true,
		},
		{
			name:          "Generic component: nil APIServer profile = no result populated",
			tlsVersions:   []string{"TLSv1.3"},
			ciphers:       []string{"TLS_AKE_WITH_AES_256_GCM_SHA384"},
			profile:       &k8s.TLSSecurityProfile{},
			componentType: GenericComponent,
			checkAPI:      false,
		},
		{
			name:          "Ingress component: uses IngressController profile",
			tlsVersions:   []string{"TLSv1.2", "TLSv1.3"},
			ciphers:       []string{"TLS_AKE_WITH_AES_256_GCM_SHA384", "TLS_AKE_WITH_AES_128_GCM_SHA256"},
			profile:       intermediateProfile(),
			componentType: IngressComponent,
			wantVersion:   true,
			wantCiphers:   true,
			wantProfile:   "Intermediate",
			checkIngress:  true,
		},
		{
			name:          "Ingress component: nil IngressController profile = no result populated",
			tlsVersions:   []string{"TLSv1.3"},
			ciphers:       []string{"TLS_AKE_WITH_AES_256_GCM_SHA384"},
			profile:       &k8s.TLSSecurityProfile{},
			componentType: IngressComponent,
			checkIngress:  false,
		},
		{
			name:          "Kubelet component: uses KubeletConfig profile",
			tlsVersions:   []string{"TLSv1.2"},
			ciphers:       []string{"TLS_AKE_WITH_AES_256_GCM_SHA384", "TLS_AKE_WITH_AES_128_GCM_SHA256"},
			profile:       intermediateProfile(),
			componentType: KubeletComponent,
			wantVersion:   true,
			wantCiphers:   true,
			checkKubelet:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pr := &PortResult{
				TlsVersions: tt.tlsVersions,
				TlsCiphers:  tt.ciphers,
			}
			CheckCompliance(pr, tt.profile, tt.componentType)

			// Verify that only the expected compliance field is populated.
			if tt.checkAPI {
				if pr.APIServerTLSConfigCompliance == nil {
					t.Fatal("APIServerTLSConfigCompliance is nil, want populated")
				}
				if pr.APIServerTLSConfigCompliance.Version != tt.wantVersion {
					t.Errorf("API version compliance = %v, want %v", pr.APIServerTLSConfigCompliance.Version, tt.wantVersion)
				}
				if pr.APIServerTLSConfigCompliance.Ciphers != tt.wantCiphers {
					t.Errorf("API cipher compliance = %v, want %v", pr.APIServerTLSConfigCompliance.Ciphers, tt.wantCiphers)
				}
				if tt.wantProfile != "" && pr.APIServerTLSConfigCompliance.ConfiguredProfile != tt.wantProfile {
					t.Errorf("API configured profile = %q, want %q", pr.APIServerTLSConfigCompliance.ConfiguredProfile, tt.wantProfile)
				}
				if pr.IngressTLSConfigCompliance != nil {
					t.Error("IngressTLSConfigCompliance should be nil for GenericComponent")
				}
				if pr.KubeletTLSConfigCompliance != nil {
					t.Error("KubeletTLSConfigCompliance should be nil for GenericComponent")
				}
			}

			if tt.checkIngress {
				if pr.IngressTLSConfigCompliance == nil {
					t.Fatal("IngressTLSConfigCompliance is nil, want populated")
				}
				if pr.IngressTLSConfigCompliance.Version != tt.wantVersion {
					t.Errorf("Ingress version compliance = %v, want %v", pr.IngressTLSConfigCompliance.Version, tt.wantVersion)
				}
				if pr.IngressTLSConfigCompliance.Ciphers != tt.wantCiphers {
					t.Errorf("Ingress cipher compliance = %v, want %v", pr.IngressTLSConfigCompliance.Ciphers, tt.wantCiphers)
				}
				if tt.wantProfile != "" && pr.IngressTLSConfigCompliance.ConfiguredProfile != tt.wantProfile {
					t.Errorf("Ingress configured profile = %q, want %q", pr.IngressTLSConfigCompliance.ConfiguredProfile, tt.wantProfile)
				}
				if pr.APIServerTLSConfigCompliance != nil {
					t.Error("APIServerTLSConfigCompliance should be nil for IngressComponent")
				}
				if pr.KubeletTLSConfigCompliance != nil {
					t.Error("KubeletTLSConfigCompliance should be nil for IngressComponent")
				}
			}

			if tt.checkKubelet {
				if pr.KubeletTLSConfigCompliance == nil {
					t.Fatal("KubeletTLSConfigCompliance is nil, want populated")
				}
				if pr.KubeletTLSConfigCompliance.Version != tt.wantVersion {
					t.Errorf("Kubelet version compliance = %v, want %v", pr.KubeletTLSConfigCompliance.Version, tt.wantVersion)
				}
				if pr.KubeletTLSConfigCompliance.Ciphers != tt.wantCiphers {
					t.Errorf("Kubelet cipher compliance = %v, want %v", pr.KubeletTLSConfigCompliance.Ciphers, tt.wantCiphers)
				}
				if pr.APIServerTLSConfigCompliance != nil {
					t.Error("APIServerTLSConfigCompliance should be nil for KubeletComponent")
				}
				if pr.IngressTLSConfigCompliance != nil {
					t.Error("IngressTLSConfigCompliance should be nil for KubeletComponent")
				}
			}

			if !tt.checkAPI && !tt.checkIngress && !tt.checkKubelet {
				if pr.APIServerTLSConfigCompliance != nil || pr.IngressTLSConfigCompliance != nil || pr.KubeletTLSConfigCompliance != nil {
					t.Error("all compliance fields should be nil when no profile is available")
				}
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
			name:     "empty expected = compliant",
			got:      []string{"TLS_AKE_WITH_AES_256_GCM_SHA384"},
			expected: nil,
			want:     true,
		},
		{
			name:     "both empty = compliant",
			got:      nil,
			expected: nil,
			want:     true,
		},
		{
			name:     "empty got with expected = non-compliant",
			got:      nil,
			expected: []string{"TLS_AES_256_GCM_SHA384"},
			want:     false,
		},
		{
			name:     "matching ciphers via IANA map",
			got:      []string{"TLS_AKE_WITH_AES_256_GCM_SHA384"},
			expected: []string{"TLS_AES_256_GCM_SHA384"},
			want:     true,
		},
		{
			name:     "corrected ECDHE-RSA IANA mapping",
			got:      []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			expected: []string{"ECDHE-RSA-AES128-GCM-SHA256"},
			want:     true,
		},
		{
			name:     "corrected ECDHE-ECDSA IANA mapping",
			got:      []string{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
			expected: []string{"ECDHE-ECDSA-AES256-GCM-SHA384"},
			want:     true,
		},
		{
			name:     "corrected DHE-RSA IANA mapping",
			got:      []string{"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"},
			expected: []string{"DHE-RSA-AES256-GCM-SHA384"},
			want:     true,
		},
		{
			name:     "corrected static RSA IANA mapping",
			got:      []string{"TLS_RSA_WITH_AES_128_GCM_SHA256"},
			expected: []string{"AES128-GCM-SHA256"},
			want:     true,
		},
		{
			name:     "IANA fallback — cipher already in OpenSSL format matches expected",
			got:      []string{"ECDHE-RSA-AES128-GCM-SHA256"},
			expected: []string{"ECDHE-RSA-AES128-GCM-SHA256"},
			want:     true,
		},
		{
			name:     "IANA fallback — unmapped cipher not in expected set",
			got:      []string{"ECDHE-RSA-AES128-GCM-SHA256"},
			expected: []string{"AES256-GCM-SHA384"},
			want:     false,
		},
		{
			name:     "unrecognized cipher = non-compliant",
			got:      []string{"TOTALLY_UNKNOWN_CIPHER"},
			expected: []string{"TLS_AES_256_GCM_SHA384"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkCipherCompliance(tt.got, tt.expected)
			if got != tt.want {
				t.Errorf("checkCipherCompliance() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasComplianceFailures(t *testing.T) {
	tests := []struct {
		name    string
		results ScanResults
		want    bool
	}{
		{
			name: "APIServer compliant = no failure",
			results: ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{
						APIServerTLSConfigCompliance: &TLSConfigComplianceResult{Version: true, Ciphers: true},
					}},
				}},
			},
			want: false,
		},
		{
			name: "Ingress compliant = no failure",
			results: ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{
						IngressTLSConfigCompliance: &TLSConfigComplianceResult{Version: true, Ciphers: true},
					}},
				}},
			},
			want: false,
		},
		{
			name: "Kubelet compliant = no failure",
			results: ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{
						KubeletTLSConfigCompliance: &TLSConfigComplianceResult{Version: true, Ciphers: true},
					}},
				}},
			},
			want: false,
		},
		{
			name: "APIServer version failure = failure",
			results: ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{
						APIServerTLSConfigCompliance: &TLSConfigComplianceResult{Version: false, Ciphers: true},
					}},
				}},
			},
			want: true,
		},
		{
			name: "Ingress cipher failure = failure",
			results: ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{
						IngressTLSConfigCompliance: &TLSConfigComplianceResult{Version: true, Ciphers: false},
					}},
				}},
			},
			want: true,
		},
		{
			name: "Kubelet version failure = failure",
			results: ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{
						KubeletTLSConfigCompliance: &TLSConfigComplianceResult{Version: false, Ciphers: true},
					}},
				}},
			},
			want: true,
		},
		{
			name: "nil compliance = no failure",
			results: ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{
						Status: StatusOK,
					}},
				}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasComplianceFailures(tt.results)
			if got != tt.want {
				t.Errorf("HasComplianceFailures() = %v, want %v", got, tt.want)
			}
		})
	}
}
