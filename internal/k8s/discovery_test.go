package k8s

import (
	"reflect"
	"sort"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestParseProcNetTCPWithAddrs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[int]string
	}{
		{
			name: "ipv4 localhost and wildcard",
			input: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2438 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0`,
			want: map[int]string{9272: "127.0.0.1", 8080: "0.0.0.0"},
		},
		{
			name: "ipv6 localhost",
			input: `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:2710 00000000000000000000000000000000:0000 0A`,
			want: map[int]string{10000: "::1"},
		},
		{
			name: "ipv6 wildcard",
			input: `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A`,
			want: map[int]string{443: "::"},
		},
		{
			name: "wildcard before localhost — wildcard wins",
			input: `  sl  local_address rem_address   st
   0: 00000000:01BB 00000000:0000 0A
   1: 0100007F:01BB 00000000:0000 0A`,
			want: map[int]string{443: "0.0.0.0"},
		},
		{
			name: "localhost before wildcard — wildcard still wins",
			input: `  sl  local_address rem_address   st
   0: 0100007F:01BB 00000000:0000 0A
   1: 00000000:01BB 00000000:0000 0A`,
			want: map[int]string{443: "0.0.0.0"},
		},
		{
			name: "two localhost rows — stays localhost",
			input: `  sl  local_address rem_address   st
   0: 0100007F:1F90 00000000:0000 0A
   1: 0100007F:1F90 00000000:0000 0A`,
			want: map[int]string{8080: "127.0.0.1"},
		},
		{
			name: "non-listen state skipped",
			input: `  sl  local_address rem_address   st
   0: 0100007F:C350 AC100164:01BB 01
   1: 00000000:01BB 00000000:0000 0A`,
			want: map[int]string{443: "0.0.0.0"},
		},
		{
			name:  "empty input",
			input: "",
			want:  map[int]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseProcNetTCPWithAddrs(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseProcNetTCPWithAddrs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeProcNetAddr(t *testing.T) {
	tests := []struct {
		hex  string
		want string
	}{
		{"0100007F", "127.0.0.1"},
		{"00000000", "0.0.0.0"},
		{"0101A8C0", "192.168.1.1"},
		{"00000000000000000000000001000000", "::1"},
		{"00000000000000000000000000000000", "::"},
		{"invalid!", "invalid!"},
	}

	for _, tt := range tests {
		t.Run(tt.hex, func(t *testing.T) {
			got := decodeProcNetAddr(tt.hex)
			if got != tt.want {
				t.Errorf("decodeProcNetAddr(%q) = %q, want %q", tt.hex, got, tt.want)
			}
		})
	}
}

func TestParseProcNetTCP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []int
	}{
		{
			name: "standard ipv4 listeners",
			input: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0100007F:2710 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0`,
			want: []int{443, 8080, 10000},
		},
		{
			name: "mixed listen and established",
			input: `  sl  local_address rem_address   st
   0: 00000000:01BB 00000000:0000 0A
   1: 0100007F:C350 AC100164:01BB 01
   2: 00000000:1F90 00000000:0000 0A`,
			want: []int{443, 8080},
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name: "header only",
			input: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode`,
			want:  nil,
		},
		{
			name: "no listeners",
			input: `  sl  local_address rem_address   st
   0: 0100007F:C350 AC100164:01BB 01
   1: 0100007F:C351 AC100164:01BB 06`,
			want: nil,
		},
		{
			name: "ipv6 listeners",
			input: `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A
   1: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A`,
			want: []int{8080, 80},
		},
		{
			name: "duplicate ports deduplicated",
			input: `  sl  local_address rem_address   st
   0: 00000000:01BB 00000000:0000 0A
   1: 0100007F:01BB 00000000:0000 0A`,
			want: []int{443},
		},
		{
			name: "malformed lines skipped",
			input: `  sl  local_address rem_address   st
   0: 00000000:01BB 00000000:0000 0A
   garbage line
   1: badformat 0A
   2: 00000000:0050 00000000:0000 0A`,
			want: []int{443, 80},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseProcNetTCP(tt.input)
			sort.Ints(got)
			sort.Ints(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseProcNetTCP() = %v, want %v", got, tt.want)
			}
		})
	}
}
func intPort(n int) intstr.IntOrString     { return intstr.FromInt(n) }
func namedPort(s string) intstr.IntOrString { return intstr.FromString(s) }

func httpProbe(port intstr.IntOrString) *v1.Probe {
	return &v1.Probe{ProbeHandler: v1.ProbeHandler{HTTPGet: &v1.HTTPGetAction{Port: port, Scheme: v1.URISchemeHTTP}}}
}

func httpsProbe(port intstr.IntOrString) *v1.Probe {
	return &v1.Probe{ProbeHandler: v1.ProbeHandler{HTTPGet: &v1.HTTPGetAction{Port: port, Scheme: v1.URISchemeHTTPS}}}
}

func tcpProbe(port intstr.IntOrString) *v1.Probe {
	return &v1.Probe{ProbeHandler: v1.ProbeHandler{TCPSocket: &v1.TCPSocketAction{Port: port}}}
}

func grpcProbe(port int32) *v1.Probe {
	return &v1.Probe{ProbeHandler: v1.ProbeHandler{GRPC: &v1.GRPCAction{Port: port}}}
}

func TestGetPlaintextProbePorts(t *testing.T) {
	tests := []struct {
		name string
		pod  *v1.Pod
		want map[int]bool
	}{
		{
			name: "http liveness probe by integer port",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: v1.PodSpec{Containers: []v1.Container{
					{Name: "c", LivenessProbe: httpProbe(intPort(10301))},
				}},
			},
			want: map[int]bool{10301: true},
		},
		{
			name: "http liveness probe via named port",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: v1.PodSpec{Containers: []v1.Container{
					{
						Name: "c",
						Ports: []v1.ContainerPort{
							{Name: "healthz", ContainerPort: 10301, Protocol: v1.ProtocolTCP},
						},
						LivenessProbe: httpProbe(namedPort("healthz")),
					},
				}},
			},
			want: map[int]bool{10301: true},
		},
		{
			name: "https liveness probe is NOT skipped",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: v1.PodSpec{Containers: []v1.Container{
					{Name: "c", LivenessProbe: httpsProbe(intPort(8443))},
				}},
			},
			want: map[int]bool{},
		},
		{
			name: "tcp readiness probe",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: v1.PodSpec{Containers: []v1.Container{
					{Name: "c", ReadinessProbe: tcpProbe(intPort(9090))},
				}},
			},
			want: map[int]bool{9090: true},
		},
		{
			name: "grpc startup probe",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: v1.PodSpec{Containers: []v1.Container{
					{Name: "c", StartupProbe: grpcProbe(5000)},
				}},
			},
			want: map[int]bool{5000: true},
		},
		{
			name: "all three probe types across multiple containers",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: v1.PodSpec{Containers: []v1.Container{
					{
						Name:           "c1",
						LivenessProbe:  httpProbe(intPort(8081)),
						ReadinessProbe: httpsProbe(intPort(8443)), // HTTPS — must not be skipped
					},
					{
						Name:         "c2",
						StartupProbe: tcpProbe(intPort(9000)),
					},
				}},
			},
			want: map[int]bool{8081: true, 9000: true},
		},
		{
			name: "named port not found returns zero — port excluded",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: v1.PodSpec{Containers: []v1.Container{
					{Name: "c", LivenessProbe: httpProbe(namedPort("missing"))},
				}},
			},
			want: map[int]bool{},
		},
		{
			name: "no probes",
			pod: &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: v1.PodSpec{Containers: []v1.Container{
					{Name: "c"},
				}},
			},
			want: map[int]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetPlaintextProbePorts(tt.pod)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPlaintextProbePorts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnionPorts(t *testing.T) {
	tests := []struct {
		name string
		a, b []int
		want []int
	}{
		{
			name: "disjoint",
			a:    []int{80, 443},
			b:    []int{8080, 9090},
			want: []int{80, 443, 8080, 9090},
		},
		{
			name: "overlapping",
			a:    []int{80, 443, 8080},
			b:    []int{443, 8080, 9090},
			want: []int{80, 443, 8080, 9090},
		},
		{
			name: "a empty",
			a:    nil,
			b:    []int{443},
			want: []int{443},
		},
		{
			name: "both empty",
			a:    nil,
			b:    nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UnionPorts(tt.a, tt.b)
			sort.Ints(got)
			sort.Ints(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnionPorts() = %v, want %v", got, tt.want)
			}
		})
	}
}
