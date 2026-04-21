package k8s

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestEnforceTLSConfigComplianceFailures(t *testing.T) {
	tests := []struct {
		name    string
		in      configv1.TLSAdherencePolicy
		enforce bool
	}{
		{"empty is legacy", configv1.TLSAdherencePolicyNoOpinion, false},
		{"legacy explicit", configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly, false},
		{"strict", configv1.TLSAdherencePolicyStrictAllComponents, true},
		{"unknown defaults strict", "FutureStrictMode", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EnforceTLSConfigComplianceFailures(tt.in); got != tt.enforce {
				t.Errorf("EnforceTLSConfigComplianceFailures(%q) = %v, want %v", tt.in, got, tt.enforce)
			}
		})
	}
}
