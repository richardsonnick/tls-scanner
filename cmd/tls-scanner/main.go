package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/openshift/tls-scanner/internal/k8s"
	"github.com/openshift/tls-scanner/internal/output"
	"github.com/openshift/tls-scanner/internal/scanner"
	"github.com/openshift/tls-scanner/internal/timing"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) (exitCode int) {
	var finalScanResults *scanner.ScanResults
	var isPQCCheck bool

	defer func() {
		if finalScanResults == nil {
			return
		}
		if isPQCCheck {
			// SkipUnscannable excludes NoPorts/LocalhostOnly/NoTLS — swap with a custom PortFilter if rules change
			if scanner.HasPQCComplianceFailures(*finalScanResults, scanner.SkipUnscannable) {
				fmt.Println("\nPQC COMPLIANCE CHECK: FAILED")
				fmt.Println("One or more endpoints do not support TLS 1.3 + ML-KEM (x25519mlkem768 or mlkem768)")
				exitCode = 1
				return
			}
			fmt.Println("\nPQC COMPLIANCE CHECK: PASSED")
			fmt.Println("All endpoints support TLS 1.3 + ML-KEM")
		} else {
			if scanner.HasComplianceFailures(*finalScanResults) {
				exitCode = 1
			}
		}
	}()

	fs := flag.NewFlagSet("tls-scanner", flag.ContinueOnError)
	host := fs.String("host", "127.0.0.1", "The target host or IP address to scan")
	port := fs.String("port", "443", "The target port to scan")
	artifactDir := fs.String("artifact-dir", "/tmp", "Directory to save the artifacts to")
	jsonFile := fs.String("json-file", "", "Output results in JSON format to specified file in artifact-dir")
	csvFile := fs.String("csv-file", "", "Output results in CSV format to specified file in artifact-dir")
	junitFile := fs.String("junit-file", "", "Output results in JUnit XML format to specified file in artifact-dir")
	concurrentScans := fs.Int("j", 0, "Number of concurrent scans; 0 = runtime.NumCPU()")
	allPods := fs.Bool("all-pods", false, "Scan all pods in the cluster (overrides --host)")
	componentFilter := fs.String("component-filter", "", "Filter pods by a comma-separated list of component names (only used with --all-pods)")
	namespaceFilter := fs.String("namespace-filter", "", "Filter pods by a comma-separated list of namespaces (only used with --all-pods)")
	targets := fs.String("targets", "", "A comma-separated list of host:port targets to scan")
	limitIPs := fs.Int("limit-ips", 0, "Limit the number of IPs to scan for testing purposes (0 = no limit)")
	logFile := fs.String("log-file", "", "Redirect all log output to the specified file")
	pqcCheck := fs.Bool("pqc-check", false, "Quick check for TLS 1.3 and ML-KEM (post-quantum) support only")
	timingFile := fs.String("timing-file", "", "Output timing report to specified file in artifact-dir")
	showVersion := fs.Bool("version", false, "Print version and exit")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Printf("tls-scanner %s (commit: %s)\n", version, commit)
		return 0
	}

	isPQCCheck = *pqcCheck

	defer func() {
		if *timingFile != "" {
			path := filepath.Join(*artifactDir, *timingFile)
			if err := timing.Timings.WriteReport(path); err != nil {
				log.Printf("Warning: Could not write timing report: %v", err)
			} else {
				log.Printf("Timing report written to %s", path)
			}
		}
	}()

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("error opening file: %v", err)
			return 1
		}
		defer func() {
			if cerr := f.Close(); cerr != nil {
				log.Printf("Warning: failed to close log file: %v", cerr)
			}
		}()
		log.SetOutput(f)
		log.Printf("Logging to file: %s", *logFile)
	}

	if !scanner.IsTestSSLInstalled() {
		log.Print("Error: testssl.sh is not installed or not in the system's PATH.")
		return 1
	}

	if *concurrentScans == 0 {
		*concurrentScans = runtime.NumCPU()
		log.Printf("Concurrency: %d (from CPU count)", *concurrentScans)
	} else if *concurrentScans < 0 {
		log.Print("Error: Number of concurrent scans must be >= 0 (0 = auto)")
		return 1
	}

	var client *k8s.Client
	var err error
	var pods []k8s.PodInfo

	if *targets != "" {
		targetList := strings.Split(*targets, ",")
		if len(targetList) == 0 || (len(targetList) == 1 && targetList[0] == "") {
			log.Print("Error: --targets flag provided but no targets were specified")
			return 1
		}

		var jobs []scanner.ScanJob
		for _, t := range targetList {
			parts := strings.Split(t, ":")
			if len(parts) != 2 {
				log.Printf("Warning: Skipping invalid target format: %s (expected host:port)", t)
				continue
			}
			p, err := strconv.Atoi(parts[1])
			if err != nil {
				log.Printf("Warning: Skipping invalid port: %s", parts[1])
				continue
			}
			jobs = append(jobs, scanner.ScanJob{IP: parts[0], Port: p})
		}

		if len(jobs) == 0 {
			log.Print("Error: No valid targets found in --targets flag")
			return 1
		}

		scanResults := scanner.Scan(jobs, *concurrentScans, nil, nil)
		finalScanResults = &scanResults

		if err := output.WriteOutputFiles(scanResults, *artifactDir, *jsonFile, *csvFile, *junitFile, isPQCCheck); err != nil {
			log.Printf("Error writing output files: %v", err)
			return 1
		}
		if isPQCCheck {
			output.PrintPQCClusterResults(scanResults)
		} else if *jsonFile == "" && *csvFile == "" && *junitFile == "" {
			output.PrintClusterResults(scanResults)
		}

		return
	}

	if *allPods {
		client, err = k8s.NewClient()
		if err != nil {
			log.Printf("Could not create kubernetes client for --all-pods: %v", err)
			return 1
		}

		pods, err = client.GetAllPodsInfo()
		if err != nil {
			log.Printf("Error listing pods: %v", err)
			return 1
		}
		pods = client.FilterPodsByComponent(pods, *componentFilter)
		pods = k8s.FilterPodsByNamespace(pods, *namespaceFilter)

		if len(pods) == 0 {
			log.Print("Warning: no pods found matching the given filters, nothing to scan")
			return 0
		}

		log.Printf("Found %d pods to scan from the cluster.", len(pods))

		if *limitIPs > 0 {
			totalIPs := 0
			for _, pod := range pods {
				totalIPs += len(pod.IPs)
			}

			if totalIPs > *limitIPs {
				log.Printf("Limiting scan to %d IPs (found %d total IPs)", *limitIPs, totalIPs)
				pods = scanner.LimitPodsToIPCount(pods, *limitIPs)
				limitedTotal := 0
				for _, pod := range pods {
					limitedTotal += len(pod.IPs)
				}
				log.Printf("After limiting: %d pods with %d total IPs", len(pods), limitedTotal)
			}
		}
	}

	if len(pods) > 0 {
		scanResults := scanner.PerformClusterScan(pods, *concurrentScans, client)
		finalScanResults = &scanResults

		if err := output.WriteOutputFiles(scanResults, *artifactDir, *jsonFile, *csvFile, *junitFile, isPQCCheck); err != nil {
			log.Printf("Error writing output files: %v", err)
			return 1
		}
		if isPQCCheck {
			output.PrintPQCClusterResults(scanResults)
		} else if *jsonFile == "" && *csvFile == "" && *junitFile == "" {
			output.PrintClusterResults(scanResults)
		}

		return
	}

	portNum, err := strconv.Atoi(*port)
	if err != nil {
		log.Printf("Invalid port: %s", *port)
		return 1
	}

	jobs := []scanner.ScanJob{{IP: *host, Port: portNum}}
	scanResults := scanner.Scan(jobs, *concurrentScans, client, nil)
	finalScanResults = &scanResults

	if err := output.WriteOutputFiles(scanResults, *artifactDir, *jsonFile, *csvFile, *junitFile, isPQCCheck); err != nil {
		log.Printf("Error writing output files: %v", err)
		return 1
	}
	if isPQCCheck {
		output.PrintPQCClusterResults(scanResults)
	} else if *jsonFile == "" && *csvFile == "" && *junitFile == "" {
		output.PrintParsedResults(scanResults)
	}

	return
}
