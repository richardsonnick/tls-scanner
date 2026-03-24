package k8s

import (
	"testing"
)

// newTestClient returns a Client with all internal maps initialised, suitable
// for unit tests that don't need a real Kubernetes API server.
func newTestClient() *Client {
	return &Client{
		processNameMap:            make(map[string]map[int]string),
		listenInfoMap:             make(map[string]map[int]ListenInfo),
		procListenAddrMap:         make(map[string]map[int]string),
		processDiscoveryAttempted: make(map[string]bool),
	}
}

func TestIsLocalhostOnly_lsofData(t *testing.T) {
	c := newTestClient()

	// Populate listenInfoMap as lsof would.
	c.listenInfoMap["10.0.0.1"] = map[int]ListenInfo{
		9259: {Port: 9259, ListenAddress: "127.0.0.1", ProcessName: "myprocess"},
		9258: {Port: 9258, ListenAddress: "*", ProcessName: "myprocess"},
	}

	tests := []struct {
		port      int
		wantIs    bool
		wantAddr  string
	}{
		{9259, true, "127.0.0.1"},  // localhost in lsof data
		{9258, false, ""},          // wildcard in lsof data
		{9999, false, ""},          // unknown port
	}

	for _, tt := range tests {
		gotIs, gotAddr := c.IsLocalhostOnly("10.0.0.1", tt.port)
		if gotIs != tt.wantIs || gotAddr != tt.wantAddr {
			t.Errorf("IsLocalhostOnly(port=%d) = (%v, %q), want (%v, %q)",
				tt.port, gotIs, gotAddr, tt.wantIs, tt.wantAddr)
		}
	}
}

func TestIsLocalhostOnly_procFallback(t *testing.T) {
	c := newTestClient()

	// No lsof data at all (secondary container scenario).
	// Proc data covers all sockets via shared network namespace.
	c.procListenAddrMap["10.0.0.1"] = map[int]string{
		9260: "127.0.0.1", // secondary container's localhost port
		9261: "0.0.0.0",   // secondary container's wildcard port
	}

	tests := []struct {
		port     int
		wantIs   bool
		wantAddr string
	}{
		{9260, true, "127.0.0.1"},  // localhost via proc fallback
		{9261, false, ""},          // wildcard — not localhost
		{9999, false, ""},          // unknown
	}

	for _, tt := range tests {
		gotIs, gotAddr := c.IsLocalhostOnly("10.0.0.1", tt.port)
		if gotIs != tt.wantIs || gotAddr != tt.wantAddr {
			t.Errorf("IsLocalhostOnly(port=%d) = (%v, %q), want (%v, %q)",
				tt.port, gotIs, gotAddr, tt.wantIs, tt.wantAddr)
		}
	}
}

func TestIsLocalhostOnly_lsofTakesPrecedence(t *testing.T) {
	c := newTestClient()

	// lsof says port 9000 is wildcard; proc says it is localhost.
	// lsof should win (it has richer context from the process perspective).
	c.listenInfoMap["10.0.0.1"] = map[int]ListenInfo{
		9000: {Port: 9000, ListenAddress: "*", ProcessName: "svc"},
	}
	c.procListenAddrMap["10.0.0.1"] = map[int]string{
		9000: "127.0.0.1",
	}

	gotIs, _ := c.IsLocalhostOnly("10.0.0.1", 9000)
	if gotIs {
		t.Error("expected IsLocalhostOnly=false when lsof shows wildcard, even if proc shows localhost")
	}
}

func TestIsLocalhostOnly_ipv6Localhost(t *testing.T) {
	c := newTestClient()

	c.procListenAddrMap["10.0.0.2"] = map[int]string{
		8080: "::1",
	}

	gotIs, gotAddr := c.IsLocalhostOnly("10.0.0.2", 8080)
	if !gotIs || gotAddr != "::1" {
		t.Errorf("IsLocalhostOnly() = (%v, %q), want (true, %q)", gotIs, gotAddr, "::1")
	}
}

func TestIsLocalhostAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"localhost", true},
		{"0.0.0.0", false},
		{"::", false},
		{"*", false},
		{"10.0.0.1", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isLocalhostAddr(tt.addr)
		if got != tt.want {
			t.Errorf("isLocalhostAddr(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}
