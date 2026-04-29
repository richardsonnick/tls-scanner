package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTemplate_valid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	content := `targets:
  - host: mysvc.myns.svc.cluster.local
    ports:
      - 443
      - 8443
  - host: myroute-myproject.apps.example.com
    ports:
      - 443
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	jobs, err := LoadTemplate(path)
	if err != nil {
		t.Fatalf("LoadTemplate: %v", err)
	}
	if len(jobs) != 3 {
		t.Fatalf("got %d jobs, want 3", len(jobs))
	}
	want := []struct {
		host string
		port int
	}{
		{"mysvc.myns.svc.cluster.local", 443},
		{"mysvc.myns.svc.cluster.local", 8443},
		{"myroute-myproject.apps.example.com", 443},
	}
	for i := range want {
		if i >= len(jobs) {
			break
		}
		if jobs[i].IP != want[i].host || jobs[i].Port != want[i].port {
			t.Errorf("jobs[%d] = %s:%d, want %s:%d", i, jobs[i].IP, jobs[i].Port, want[i].host, want[i].port)
		}
	}
}

func TestLoadTemplate_missingHost(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	content := `targets:
  - host: ""
    ports:
      - 443
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadTemplate(path)
	if err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestLoadTemplate_invalidPort(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	content := `targets:
  - host: 127.0.0.1
    ports:
      - 0
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadTemplate(path)
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestLoadTemplate_emptyFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yml")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadTemplate(path)
	if err == nil {
		t.Fatal("expected error for empty template")
	}
}

func TestLoadTemplate_noPorts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.yml")
	content := `targets:
  - host: 127.0.0.1
    ports: []
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadTemplate(path)
	if err == nil {
		t.Fatal("expected error when ports is empty")
	}
}

func TestGenerateTemplate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "out.yml")
	if err := GenerateTemplate(path); err != nil {
		t.Fatal(err)
	}
	jobs, err := LoadTemplate(path)
	if err != nil {
		t.Fatalf("LoadTemplate generated file: %v", err)
	}
	if len(jobs) != 3 {
		t.Fatalf("generated template: got %d jobs, want 3", len(jobs))
	}
}
