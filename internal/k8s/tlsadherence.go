package k8s

import configv1 "github.com/openshift/api/config/v1"

// EnforceTLSConfigComplianceFailures returns whether TLS profile non-compliance
// should fail CI (exit code / JUnit), matching centralized TLS config semantics:
//   - "" (unset) and LegacyAdheringComponentsOnly → do not fail on drift
//   - StrictAllComponents → fail when scanned TLS does not match the effective profile
//   - any other value → treat as strict (unknown enum → secure default)
func EnforceTLSConfigComplianceFailures(tlsAdherence configv1.TLSAdherencePolicy) bool {
	switch tlsAdherence {
	case configv1.TLSAdherencePolicyNoOpinion, configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly:
		return false
	case configv1.TLSAdherencePolicyStrictAllComponents:
		return true
	default:
		return true
	}
}
