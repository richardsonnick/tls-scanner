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
		name              string
		tlsVersions       []string
		ciphers           []string
		profile           *k8s.TLSSecurityProfile
		wantAPIVersion    bool
		wantAPICiphers    bool
		wantAPIProfile    string
		wantIngressVer    bool
		wantIngressCipher bool
	}{
		{
			name:              "Default profile with TLS 1.2+1.3 resolved to Intermediate",
			tlsVersions:       []string{"TLSv1.2", "TLSv1.3"},
			ciphers:           []string{"TLS_AKE_WITH_AES_256_GCM_SHA384", "TLS_AKE_WITH_AES_128_GCM_SHA256"},
			profile:           defaultProfile(),
			wantAPIVersion:    true,
			wantAPICiphers:    true,
			wantAPIProfile:    "Default",
			wantIngressVer:    true,
			wantIngressCipher: true,
		},
		{
			name:              "Empty Default profile (no MinTLSVersion/Ciphers) = compliant",
			tlsVersions:       []string{"TLSv1.2", "TLSv1.3"},
			ciphers:           []string{"TLS_AKE_WITH_AES_256_GCM_SHA384"},
			profile:           emptyProfile(),
			wantAPIVersion:    true,
			wantAPICiphers:    true,
			wantAPIProfile:    "Default",
			wantIngressVer:    true,
			wantIngressCipher: true,
		},
		{
			name:              "Intermediate profile with TLS 1.2+1.3 and matching ciphers",
			tlsVersions:       []string{"TLSv1.2", "TLSv1.3"},
			ciphers:           []string{"TLS_AKE_WITH_AES_256_GCM_SHA384", "TLS_AKE_WITH_AES_128_GCM_SHA256"},
			profile:           intermediateProfile(),
			wantAPIVersion:    true,
			wantAPICiphers:    true,
			wantAPIProfile:    "Intermediate",
			wantIngressVer:    true,
			wantIngressCipher: true,
		},
		{
			name:              "Modern profile with TLS 1.3 only = version pass",
			tlsVersions:       []string{"TLSv1.3"},
			ciphers:           []string{"TLS_AKE_WITH_AES_256_GCM_SHA384"},
			profile:           modernProfile(),
			wantAPIVersion:    true,
			wantAPICiphers:    true,
			wantAPIProfile:    "Modern",
			wantIngressVer:    true,
			wantIngressCipher: true,
		},
		{
			name:              "Modern profile with TLS 1.2 = version fail",
			tlsVersions:       []string{"TLSv1.2"},
			ciphers:           []string{"TLS_AKE_WITH_AES_256_GCM_SHA384"},
			profile:           modernProfile(),
			wantAPIVersion:    false,
			wantAPICiphers:    true,
			wantAPIProfile:    "Modern",
			wantIngressVer:    false,
			wantIngressCipher: true,
		},
		{
			name:              "Intermediate profile with unknown cipher = cipher fail",
			tlsVersions:       []string{"TLSv1.2", "TLSv1.3"},
			ciphers:           []string{"UNKNOWN_CIPHER_SUITE"},
			profile:           intermediateProfile(),
			wantAPIVersion:    true,
			wantAPICiphers:    false,
			wantAPIProfile:    "Intermediate",
			wantIngressVer:    true,
			wantIngressCipher: false,
		},
		{
			name:              "Nil profile sections = no compliance populated",
			tlsVersions:       []string{"TLSv1.3"},
			ciphers:           []string{"TLS_AKE_WITH_AES_256_GCM_SHA384"},
			profile:           &k8s.TLSSecurityProfile{},
			wantAPIVersion:    false,
			wantAPICiphers:    false,
			wantAPIProfile:    "",
			wantIngressVer:    false,
			wantIngressCipher: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pr := &PortResult{
				TlsVersions: tt.tlsVersions,
				TlsCiphers:  tt.ciphers,
			}
			CheckCompliance(pr, tt.profile)

			if pr.APIServerTLSConfigCompliance.Version != tt.wantAPIVersion {
				t.Errorf("API version compliance = %v, want %v", pr.APIServerTLSConfigCompliance.Version, tt.wantAPIVersion)
			}
			if pr.APIServerTLSConfigCompliance.Ciphers != tt.wantAPICiphers {
				t.Errorf("API cipher compliance = %v, want %v", pr.APIServerTLSConfigCompliance.Ciphers, tt.wantAPICiphers)
			}
			if pr.APIServerTLSConfigCompliance.ConfiguredProfile != tt.wantAPIProfile {
				t.Errorf("API configured profile = %q, want %q", pr.APIServerTLSConfigCompliance.ConfiguredProfile, tt.wantAPIProfile)
			}
			if pr.IngressTLSConfigCompliance.Version != tt.wantIngressVer {
				t.Errorf("Ingress version compliance = %v, want %v", pr.IngressTLSConfigCompliance.Version, tt.wantIngressVer)
			}
			if pr.IngressTLSConfigCompliance.Ciphers != tt.wantIngressCipher {
				t.Errorf("Ingress cipher compliance = %v, want %v", pr.IngressTLSConfigCompliance.Ciphers, tt.wantIngressCipher)
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
			name: "all compliant",
			results: ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{
						APIServerTLSConfigCompliance: &TLSConfigComplianceResult{Version: true, Ciphers: true},
						IngressTLSConfigCompliance:   &TLSConfigComplianceResult{Version: true, Ciphers: true},
					}},
				}},
			},
			want: false,
		},
		{
			name: "API version failure",
			results: ScanResults{
				IPResults: []IPResult{{
					PortResults: []PortResult{{
						APIServerTLSConfigCompliance: &TLSConfigComplianceResult{Version: false, Ciphers: true},
						IngressTLSConfigCompliance:   &TLSConfigComplianceResult{Version: true, Ciphers: true},
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
