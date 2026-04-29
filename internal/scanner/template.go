package scanner

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ScanTemplate is the root document for a TLS scanner targets YAML file.
type ScanTemplate struct {
	Targets []TemplateTarget `yaml:"targets"`
}

// TemplateTarget groups one host with one or more TCP ports to scan.
type TemplateTarget struct {
	Host  string `yaml:"host"`
	Ports []int  `yaml:"ports"`
}

const templateSample = `# TLS Scanner targets — commit beside your component to document TLS endpoints.
# Run: tls-scanner --template this-file.yml
#
# "host" is any name or IP reachable from where you run the scanner (not pod IPs).
# Typical OpenShift/Kubernetes values: Route hostname, Ingress host, or Service DNS
# (e.g. mysvc.myns.svc.cluster.local). Replace the examples below with your real names.
#
targets:
  - host: mycomponent-myproject.apps.cluster.example.com
    ports:
      - 443
  - host: mycomponent.myproject.svc.cluster.local
    ports:
      - 443
      - 8443
`

// GenerateTemplate writes a commented sample YAML file to path.
func GenerateTemplate(path string) error {
	return os.WriteFile(path, []byte(templateSample), 0644)
}

// LoadTemplate reads a YAML template from path and returns scan jobs (one per host:port).
func LoadTemplate(path string) ([]ScanJob, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template: %w", err)
	}

	var doc ScanTemplate
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse template YAML: %w", err)
	}

	if len(doc.Targets) == 0 {
		return nil, fmt.Errorf("template has no targets")
	}

	var jobs []ScanJob
	for ti, t := range doc.Targets {
		host := strings.TrimSpace(t.Host)
		if host == "" {
			return nil, fmt.Errorf("targets[%d]: host is required", ti)
		}
		host = normalizeTemplateHost(host)
		if len(t.Ports) == 0 {
			return nil, fmt.Errorf("targets[%d] (%s): at least one port is required", ti, host)
		}
		for pi, port := range t.Ports {
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("targets[%d] (%s): invalid port %d at index %d (want 1-65535)", ti, host, port, pi)
			}
			jobs = append(jobs, ScanJob{IP: host, Port: port})
		}
	}

	if len(jobs) == 0 {
		return nil, fmt.Errorf("template produced no scan jobs")
	}

	return jobs, nil
}

func normalizeTemplateHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") && len(host) >= 2 {
		return host[1 : len(host)-1]
	}
	return host
}
