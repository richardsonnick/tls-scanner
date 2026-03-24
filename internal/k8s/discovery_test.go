package k8s

import (
	"reflect"
	"sort"
	"testing"
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
			name: "duplicate port keeps first",
			input: `  sl  local_address rem_address   st
   0: 00000000:01BB 00000000:0000 0A
   1: 0100007F:01BB 00000000:0000 0A`,
			want: map[int]string{443: "0.0.0.0"},
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
