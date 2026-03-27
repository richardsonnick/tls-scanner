package scanner

import (
	"testing"
)

func TestPolicy(t *testing.T) {
	p := Policy()
	if p == nil {
		t.Fatal("Policy() returned nil")
	}
	if len(p.Rules) == 0 {
		t.Fatal("Policy() has no rules")
	}
}

func TestPolicyResolve(t *testing.T) {
	tests := []struct {
		name      string
		rules     []PolicyRule
		namespace string
		process   string
		component string
		port      int
		want      ComponentType
	}{
		{
			name:  "no rules = generic",
			rules: nil,
			port:  443,
			want:  GenericComponent,
		},
		{
			name:      "namespace match → ingress",
			rules:     []PolicyRule{{Namespace: "openshift-ingress", Profile: ProfileIngress}},
			namespace: "openshift-ingress",
			port:      443,
			want:      IngressComponent,
		},
		{
			name:      "namespace mismatch = generic",
			rules:     []PolicyRule{{Namespace: "openshift-ingress", Profile: ProfileIngress}},
			namespace: "openshift-kube-apiserver",
			port:      443,
			want:      GenericComponent,
		},
		{
			name:  "port match → kubelet",
			rules: []PolicyRule{{Port: intPtr(10250), Profile: ProfileKubelet}},
			port:  10250,
			want:  KubeletComponent,
		},
		{
			name:  "port mismatch = generic",
			rules: []PolicyRule{{Port: intPtr(10250), Profile: ProfileKubelet}},
			port:  443,
			want:  GenericComponent,
		},
		{
			name:    "process match → kubelet",
			rules:   []PolicyRule{{Process: "kubelet", Profile: ProfileKubelet}},
			process: "kubelet",
			port:    443,
			want:    KubeletComponent,
		},
		{
			name:      "component match → ingress",
			rules:     []PolicyRule{{Component: "router", Profile: ProfileIngress}},
			component: "router",
			port:      443,
			want:      IngressComponent,
		},
		{
			name: "first rule wins",
			rules: []PolicyRule{
				{Namespace: "openshift-ingress", Profile: ProfileIngress},
				{Port: intPtr(443), Profile: ProfileKubelet},
			},
			namespace: "openshift-ingress",
			port:      443,
			want:      IngressComponent,
		},
		{
			name: "multi-field AND: all match",
			rules: []PolicyRule{
				{Namespace: "openshift-ingress", Port: intPtr(443), Profile: ProfileIngress},
			},
			namespace: "openshift-ingress",
			port:      443,
			want:      IngressComponent,
		},
		{
			name: "multi-field AND: one field mismatches = no match",
			rules: []PolicyRule{
				{Namespace: "openshift-ingress", Port: intPtr(443), Profile: ProfileIngress},
			},
			namespace: "openshift-ingress",
			port:      8443,
			want:      GenericComponent,
		},
		{
			name:  "apiserver profile rule → generic component",
			rules: []PolicyRule{{Port: intPtr(6443), Profile: ProfileAPIServer}},
			port:  6443,
			want:  GenericComponent,
		},
		{
			name:  "empty rule (all wildcards) matches everything",
			rules: []PolicyRule{{Profile: ProfileKubelet}},
			port:  1234,
			want:  KubeletComponent,
		},
		{
			name:      "namespace regex prefix match",
			rules:     []PolicyRule{{Namespace: "openshift-.*", Profile: ProfileIngress}},
			namespace: "openshift-ingress",
			port:      443,
			want:      IngressComponent,
		},
		{
			name:      "namespace regex does not match different prefix",
			rules:     []PolicyRule{{Namespace: "openshift-.*", Profile: ProfileIngress}},
			namespace: "kube-system",
			port:      443,
			want:      GenericComponent,
		},
		{
			name:    "process regex matches kubelet variant",
			rules:   []PolicyRule{{Process: "kubelet.*", Profile: ProfileKubelet}},
			process: "kubelet-extra",
			port:    443,
			want:    KubeletComponent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &ComponentPolicy{Rules: tt.rules}
			for i := range policy.Rules {
				if err := policy.Rules[i].compile(); err != nil {
					t.Fatalf("rule %d: compile error: %v", i, err)
				}
			}
			got := policy.Resolve(tt.namespace, tt.process, tt.component, tt.port)
			if got != tt.want {
				t.Errorf("Resolve(%q, %q, %q, %d) = %v, want %v",
					tt.namespace, tt.process, tt.component, tt.port, got, tt.want)
			}
		})
	}
}

func TestPolicyBehaviour(t *testing.T) {
	p := Policy()

	tests := []struct {
		name      string
		namespace string
		process   string
		component string
		port      int
		want      ComponentType
	}{
		{
			// Ingress controller pods run in openshift-ingress and should be
			// checked against the IngressController TLS profile.
			name:      "ingress-controller conforms to ingress profile",
			namespace: "openshift-ingress",
			process:   "router",
			port:      443,
			want:      IngressComponent,
		},
		{
			// Kubelet is identified by process name and should be checked
			// against the KubeletConfig TLS profile.
			name:    "kubelet conforms to kubelet profile",
			process: "kubelet",
			port:    10250,
			want:    KubeletComponent,
		},
		{
			// Kubelet identification falls back to well-known port when
			// process name is not available.
			name: "kubelet identified by port when process name unavailable",
			port: 10250,
			want: KubeletComponent,
		},
		{
			// Any other component defaults to the cluster-wide APIServer profile.
			name:      "generic component conforms to APIServer profile",
			namespace: "openshift-kube-apiserver",
			process:   "kube-apiserver",
			port:      6443,
			want:      GenericComponent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.Resolve(tt.namespace, tt.process, tt.component, tt.port)
			if got != tt.want {
				t.Errorf("Policy().Resolve(%q, %q, %q, %d) = %v, want %v",
					tt.namespace, tt.process, tt.component, tt.port, got, tt.want)
			}
		})
	}
}

func intPtr(v int) *int { return &v }
