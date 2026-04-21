package k8s

import configv1 "github.com/openshift/api/config/v1"

// EnforceTLSConfigComplianceFailures returns whether TLS profile non-compliance
// should fail CI (exit code / JUnit), matching centralized TLS config semantics:
//   - "" (unset) and LegacyAdheringComponentsOnly → do not fail on drift
func EnforceTLSConfigComplianceFailures(tlsAdherence configv1.TLSAdherencePolicy) bool {
	return tlsAdherence != configv1.TLSAdherencePolicyNoOpinion &&
		tlsAdherence != configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly
}
