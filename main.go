package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
)

func main() {
	var finalScanResults *ScanResults
	var isPQCCheck bool
	defer func() {
		if finalScanResults != nil {
			if isPQCCheck {
				if hasPQCComplianceFailures(*finalScanResults) {
					os.Exit(1)
				}
			} else {
				if hasComplianceFailures(*finalScanResults) {
					os.Exit(1)
				}
			}
		}
	}()

	host := flag.String("host", "127.0.0.1", "The target host or IP address to scan")
	port := flag.String("port", "443", "The target port to scan")
	artifactDir := flag.String("artifact-dir", "/tmp", "Directory to save the artifacts to")
	jsonFile := flag.String("json-file", "", "Output results in JSON format to specified file in artifact-dir")
	csvFile := flag.String("csv-file", "", "Output results in CSV format to specified file in artifact-dir")
	junitFile := flag.String("junit-file", "", "Output results in JUnit XML format to specified file in artifact-dir")
	concurrentScans := flag.Int("j", 1, "Number of concurrent scans to run in parallel (speeds up large IP lists significantly!)")
	allPods := flag.Bool("all-pods", false, "Scan all pods in the current namespace (overrides --iplist and --host)")
	componentFilter := flag.String("component-filter", "", "Filter pods by a comma-separated list of component names (only used with --all-pods)")
	namespaceFilter := flag.String("namespace-filter", "", "Filter pods by a comma-separated list of namespaces (only used with --all-pods)")
	targets := flag.String("targets", "", "A comma-separated list of host:port targets to scan")
	limitIPs := flag.Int("limit-ips", 0, "Limit the number of IPs to scan for testing purposes (0 = no limit)")
	logFile := flag.String("log-file", "", "Redirect all log output to the specified file")
	pqcCheck := flag.Bool("pqc-check", false, "Quick check for TLS 1.3 and ML-KEM (post-quantum) support only")
	timingFile := flag.String("timing-file", "", "Output function timing report to specified file in artifact-dir")
	flag.Parse()

	defer func() {
		if *timingFile != "" {
			path := filepath.Join(*artifactDir, *timingFile)
			if err := timings.WriteReport(path); err != nil {
				log.Printf("Warning: Could not write timing report: %v", err)
			} else {
				log.Printf("Timing report written to %s", path)
			}
		}
	}()

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
		log.Printf("Logging to file: %s", *logFile)
	}

	if !isTestSSLInstalled() {
		log.Fatal("Error: testssl.sh is not installed or not in the system's PATH. This program requires testssl.sh to function.")
	}

	if *concurrentScans < 1 {
		log.Fatal("Error: Number of concurrent scans must be at least 1")
	}

	var k8sClient *K8sClient
	var err error
	var pods []PodInfo

	if *pqcCheck {
		isPQCCheck = true

		var scanResults ScanResults

		if *allPods {
			k8sClient, err = newK8sClient()
			if err != nil {
				log.Fatalf("Error creating Kubernetes client: %v", err)
			}

			pods = k8sClient.getAllPodsInfo()
			pods = k8sClient.filterPodsByComponent(pods, *componentFilter)
			pods = filterPodsByNamespace(pods, *namespaceFilter)

			if *limitIPs > 0 && len(pods) > *limitIPs {
				pods = pods[:*limitIPs]
			}

			scanResults = performPQCClusterScan(pods, k8sClient, *concurrentScans)
		} else if *targets != "" {
			targetList := strings.Split(*targets, ",")
			scanResults = performPQCScan(targetList, *concurrentScans)
		} else {
			target := fmt.Sprintf("%s:%s", *host, *port)
			scanResults = performPQCScan([]string{target}, 1)
		}

		printPQCClusterResults(scanResults)
		writeOutputFiles(scanResults, *artifactDir, *jsonFile, *csvFile, *junitFile)

		finalScanResults = &scanResults
		return
	}

	if *targets != "" {
		targetList := strings.Split(*targets, ",")
		if len(targetList) == 0 || (len(targetList) == 1 && targetList[0] == "") {
			log.Fatal("Error: --targets flag provided but no targets were specified")
		}

		targetsByHost := make(map[string][]string)
		for _, t := range targetList {
			parts := strings.Split(t, ":")
			if len(parts) != 2 {
				log.Printf("Warning: Skipping invalid target format: %s (expected host:port)", t)
				continue
			}
			host := parts[0]
			port := parts[1]
			targetsByHost[host] = append(targetsByHost[host], port)
		}

		if len(targetsByHost) == 0 {
			log.Fatal("Error: No valid targets found in --targets flag")
		}

		scanResults := performTargetsScan(targetsByHost, *concurrentScans)
		finalScanResults = &scanResults

		writeOutputFiles(scanResults, *artifactDir, *jsonFile, *csvFile, *junitFile)
		if *jsonFile == "" && *csvFile == "" && *junitFile == "" {
			printClusterResults(scanResults)
		}

		return
	}

	if *allPods {
		k8sClient, err = newK8sClient()
		if err != nil {
			log.Fatalf("Could not create kubernetes client for --all-pods: %v", err)
		}

		pods = k8sClient.getAllPodsInfo()
		pods = k8sClient.filterPodsByComponent(pods, *componentFilter)
		pods = filterPodsByNamespace(pods, *namespaceFilter)

		log.Printf("Found %d pods to scan from the cluster.", len(pods))

		// Apply IP limit if specified
		if *limitIPs > 0 {
			totalIPs := 0
			for _, pod := range pods {
				totalIPs += len(pod.IPs)
			}

			if totalIPs > *limitIPs {
				log.Printf("Limiting scan to %d IPs (found %d total IPs)", *limitIPs, totalIPs)
				pods = limitPodsToIPCount(pods, *limitIPs)
				limitedTotal := 0
				for _, pod := range pods {
					limitedTotal += len(pod.IPs)
				}
				log.Printf("After limiting: %d pods with %d total IPs", len(pods), limitedTotal)
			}
		}
	}

	if len(pods) > 0 {
		scanResults := performClusterScan(pods, *concurrentScans, k8sClient)
		finalScanResults = &scanResults

		writeOutputFiles(scanResults, *artifactDir, *jsonFile, *csvFile, *junitFile)
		if *jsonFile == "" && *csvFile == "" && *junitFile == "" {
			printClusterResults(scanResults)
		}

		return
	}

	log.Printf("Found testssl.sh. Starting scan on %s:%s...\n\n", *host, *port)

	target := fmt.Sprintf("%s:%s", *host, *port)

	// Create temp file with entropy for testssl.sh output
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("testssl-%s-%s-*.json", *host, *port))
	if err != nil {
		log.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFileName := tmpFile.Name()
	tmpFile.Close() // Close so testssl.sh can write to it
	defer os.Remove(tmpFileName)

	cmd := exec.Command("testssl.sh", "--jsonfile", tmpFileName, "--warnings", "off", "--color", "0", "--parallel", target)
	cmd.Env = append(os.Environ(), fmt.Sprintf("MAX_PARALLEL=%d", *concurrentScans))

	stopTestSSL := timings.Track("testssl.sh[full]", target)
	cmdOutput, runErr := cmd.CombinedOutput()
	stopTestSSL()
	if runErr != nil {
		// testssl.sh may return non-zero exit codes even on successful scans
		log.Printf("Warning: testssl.sh returned non-zero exit code: %v", runErr)
		log.Printf("testssl.sh output: %s", string(cmdOutput))
	}

	// Read the JSON output file
	output, readErr := os.ReadFile(tmpFileName)
	if readErr != nil {
		log.Printf("Error reading testssl.sh output file: %v", readErr)
		output = []byte{}
	}

	// Parse testssl.sh output - convert to our internal format
	scanResult := parseTestSSLOutput(output, *host, *port)

	// Extract key exchange info from raw output
	keyExchangeInfo := extractKeyExchangeFromTestSSL(output)

	// Extract TLS info for use in JSON and CSV output
	versions, ciphers, cipherStrength := extractTLSInfo(scanResult)

	// For single host scans, always create ScanResults for compliance checking
	var tlsConfig *TLSSecurityProfile
	if k8sClient != nil {
		if config, err := k8sClient.getTLSSecurityProfile(); err != nil {
			log.Printf("Warning: Could not collect TLS security profiles: %v", err)
		} else {
			tlsConfig = config
		}
	}

	// Convert single scan to ScanResults format
	portNum, _ := strconv.Atoi(*port)
	singleResult := ScanResults{
		Timestamp:         time.Now().Format(time.RFC3339),
		TotalIPs:          1,
		ScannedIPs:        1,
		TLSSecurityConfig: tlsConfig,
		IPResults: []IPResult{{
			IP:        *host,
			Status:    "scanned",
			OpenPorts: []int{portNum},
			PortResults: []PortResult{{
				Port:              portNum,
				Protocol:          "tcp",
				State:             "open",
				Service:           "ssl/tls",
				TlsVersions:       versions,
				TlsCiphers:        ciphers,
				TlsCipherStrength: cipherStrength,
				TlsKeyExchange:    keyExchangeInfo,
			}},
		}},
	}

	// Check compliance if TLS config is available
	if tlsConfig != nil && len(ciphers) > 0 {
		checkCompliance(&singleResult.IPResults[0].PortResults[0], tlsConfig)
	}

	writeOutputFiles(singleResult, *artifactDir, *jsonFile, *csvFile, *junitFile)
	if *jsonFile == "" && *csvFile == "" && *junitFile == "" {
		printParsedResults(singleResult)
	}

	finalScanResults = &singleResult
}

func writeJUnitOutput(scanResults ScanResults, filename string) error {
	testSuite := JUnitTestSuite{
		Name: "TLSSecurityScan",
	}

	for _, ipResult := range scanResults.IPResults {
		for _, portResult := range ipResult.PortResults {
			testCase := JUnitTestCase{
				Name:      fmt.Sprintf("%s:%d - %s", ipResult.IP, portResult.Port, portResult.Service),
				ClassName: ipResult.Pod.Name,
			}

			var failures []string
			if portResult.IngressTLSConfigCompliance != nil && (!portResult.IngressTLSConfigCompliance.Version || !portResult.IngressTLSConfigCompliance.Ciphers) {
				failures = append(failures, "Ingress TLS config is not compliant.")
			}
			if portResult.APIServerTLSConfigCompliance != nil && (!portResult.APIServerTLSConfigCompliance.Version || !portResult.APIServerTLSConfigCompliance.Ciphers) {
				failures = append(failures, "API Server TLS config is not compliant.")
			}
			if portResult.KubeletTLSConfigCompliance != nil && (!portResult.KubeletTLSConfigCompliance.Version || !portResult.KubeletTLSConfigCompliance.Ciphers) {
				failures = append(failures, "Kubelet TLS config is not compliant.")
			}

			if len(failures) > 0 {
				testCase.Failure = &JUnitFailure{
					Message: "TLS Compliance Failed",
					Type:    "TLSComplianceCheck",
					Content: strings.Join(failures, "\n"),
				}
				testSuite.Failures++
			}

			testSuite.TestCases = append(testSuite.TestCases, testCase)
		}
	}

	testSuite.Tests = len(testSuite.TestCases)

	// Create the directory for the file if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("could not create directory for JUnit report: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create JUnit report file: %v", err)
	}
	defer file.Close()

	if _, err := file.WriteString(xml.Header); err != nil {
		return fmt.Errorf("failed to write XML header to JUnit report: %v", err)
	}

	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")
	if err := encoder.Encode(testSuite); err != nil {
		return fmt.Errorf("could not encode JUnit report: %v", err)
	}

	return nil
}

func isTestSSLInstalled() bool {
	_, err := exec.LookPath("testssl.sh")
	return err == nil
}

// discoverPortsFromPodSpec discovers open ports by reading the pod's specification from the Kubernetes API.
// This is much more reliable and efficient than network scanning.
func discoverPortsFromPodSpec(pod *v1.Pod) ([]int, error) {
	log.Printf("Discovering ports for pod %s/%s from API server...", pod.Namespace, pod.Name)

	var ports []int
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			// We only care about TCP ports for TLS scanning
			if port.Protocol == v1.ProtocolTCP {
				ports = append(ports, int(port.ContainerPort))
			}
		}
	}

	// Also check init containers, just in case they expose a port
	for _, container := range pod.Spec.InitContainers {
		for _, port := range container.Ports {
			if port.Protocol == v1.ProtocolTCP {
				ports = append(ports, int(port.ContainerPort))
			}
		}
	}

	if len(ports) == 0 {
		log.Printf("Found 0 declared TCP ports for pod %s/%s.", pod.Namespace, pod.Name)
	} else {
		log.Printf("Found %d declared TCP ports for pod %s/%s: %v", len(ports), pod.Namespace, pod.Name, ports)
	}

	return ports, nil
}

func getMinVersionValue(versions []string) int {
	if len(versions) == 0 {
		return 0
	}
	minVersion := tlsVersionValueMap[versions[0]]
	for _, v := range versions[1:] {
		verVal := tlsVersionValueMap[v]
		if verVal < minVersion {
			minVersion = verVal
		}
	}
	return minVersion
}

func checkCompliance(portResult *PortResult, tlsProfile *TLSSecurityProfile) {
	portResultMinVersion := 0
	if portResult.TlsVersions != nil {
		portResultMinVersion = getMinVersionValue(portResult.TlsVersions)
	}

	// TODO potentially wasteful memory allocations here
	portResult.IngressTLSConfigCompliance = &TLSConfigComplianceResult{}
	portResult.APIServerTLSConfigCompliance = &TLSConfigComplianceResult{}
	portResult.KubeletTLSConfigCompliance = &TLSConfigComplianceResult{}

	if ingress := tlsProfile.IngressController; tlsProfile.IngressController != nil {
		if ingress.MinTLSVersion != "" {
			ingressMinVersion := tlsVersionValueMap[ingress.MinTLSVersion]
			portResult.IngressTLSConfigCompliance.Version = (portResultMinVersion >= ingressMinVersion)
		}
		portResult.IngressTLSConfigCompliance.Ciphers = checkCipherCompliance(portResult.TlsCiphers, ingress.Ciphers)
	}

	if api := tlsProfile.APIServer; tlsProfile.APIServer != nil {
		if api.MinTLSVersion != "" {
			apiMinVersion := tlsVersionValueMap[api.MinTLSVersion]
			portResult.APIServerTLSConfigCompliance.Version = (portResultMinVersion >= apiMinVersion)
		}
		portResult.APIServerTLSConfigCompliance.Ciphers = checkCipherCompliance(portResult.TlsCiphers, api.Ciphers)
	}

	if kube := tlsProfile.KubeletConfig; tlsProfile.KubeletConfig != nil {
		if kube.MinTLSVersion != "" {
			kubMinVersion := tlsVersionValueMap[kube.MinTLSVersion]
			portResult.KubeletTLSConfigCompliance.Version = (portResultMinVersion >= kubMinVersion)
		}
		portResult.KubeletTLSConfigCompliance.Ciphers = checkCipherCompliance(portResult.TlsCiphers, kube.TLSCipherSuites)
	}

}

func checkCipherCompliance(gotCiphers []string, expectedCiphers []string) bool {
	expectedSet := make(map[string]struct{}, len(expectedCiphers))
	for _, c := range expectedCiphers {
		expectedSet[c] = struct{}{}
	}

	if len(gotCiphers) == 0 && len(expectedCiphers) > 0 {
		return false
	}
	// TODO testssl.sh prints some cipher suites to specify that an "authenticated key exchange", AKE was used
	// We need a way to map these cipher suites to the more generic version.
	// for example TLS_AKE_WITH_AES_128_GCM_SHA256 -> TLS_AES_128_GCM_SHA256 (openssl)

	for _, cipher := range gotCiphers {
		convertedCipher := ianaCipherToOpenSSLCipherMap[cipher]
		if _, exists := expectedSet[convertedCipher]; !exists {
			return false
		}
	}

	return true
}

// hasComplianceFailures checks if any port has TLS compliance violations
func hasComplianceFailures(results ScanResults) bool {
	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			// Check Ingress compliance
			if portResult.IngressTLSConfigCompliance != nil &&
				(!portResult.IngressTLSConfigCompliance.Version || !portResult.IngressTLSConfigCompliance.Ciphers) {
				return true
			}
			// Check API Server compliance
			if portResult.APIServerTLSConfigCompliance != nil &&
				(!portResult.APIServerTLSConfigCompliance.Version || !portResult.APIServerTLSConfigCompliance.Ciphers) {
				return true
			}
			// Check Kubelet compliance
			if portResult.KubeletTLSConfigCompliance != nil &&
				(!portResult.KubeletTLSConfigCompliance.Version || !portResult.KubeletTLSConfigCompliance.Ciphers) {
				return true
			}
		}
	}
	return false
}

// TODO move to helpers
// stringInSlice returns true if the string s is present in slice list.
func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func extractTLSInfo(scanRun ScanRun) (versions []string, ciphers []string, cipherStrength map[string]string) {
	// Collect all detected ciphers and TLS versions for this port
	var allDetectedCiphers []string
	var tlsVersions []string
	cipherStrength = make(map[string]string) // TODO currently unused. Might be useful

	// Extract TLS versions and ciphers from scan results
	for _, host := range scanRun.Hosts {
		for _, tlsPort := range host.Ports {
			for _, script := range tlsPort.Scripts {
				if script.ID == "ssl-enum-ciphers" {
					for _, table := range script.Tables {
						tlsVersion := table.Key
						if tlsVersion != "" {
							tlsVersions = append(tlsVersions, tlsVersion)
						}

						// Find ciphers for this TLS version
						for _, subTable := range table.Tables {
							if subTable.Key == "ciphers" {
								var currentCipherName string
								var currentCipherStrength string
								for _, cipherTable := range subTable.Tables {
									currentCipherName = ""
									currentCipherStrength = ""
									for _, elem := range cipherTable.Elems {
										if elem.Key == "name" {
											currentCipherName = elem.Value
										} else if elem.Key == "strength" {
											currentCipherStrength = elem.Value
										}
									}
									if currentCipherName != "" && currentCipherStrength != "" {
										allDetectedCiphers = append(allDetectedCiphers, currentCipherName)
										cipherStrength[currentCipherName] = currentCipherStrength
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Remove duplicates
	allDetectedCiphers = removeDuplicates(allDetectedCiphers)
	tlsVersions = removeDuplicates(tlsVersions)

	return tlsVersions, allDetectedCiphers, cipherStrength
}

func performClusterScan(pods []PodInfo, concurrentScans int, k8sClient *K8sClient) ScanResults {
	defer timings.Track("performClusterScan", "")()
	startTime := time.Now()

	totalIPs := 0
	for _, pod := range pods {
		totalIPs += len(pod.IPs)
	}

	fmt.Printf("========================================\n")
	fmt.Printf("CONCURRENT CLUSTER SCAN STARTING\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total Pods to scan: %d\n", len(pods))
	fmt.Printf("Total IPs to scan: %d\n", totalIPs)
	fmt.Printf("Concurrent workers: %d\n", concurrentScans)
	fmt.Printf("Process detection workers: %d\n", max(2, concurrentScans/2))
	fmt.Printf("========================================\n\n")

	// Collect TLS security configuration from cluster
	var tlsConfig *TLSSecurityProfile
	if k8sClient != nil {
		if config, err := k8sClient.getTLSSecurityProfile(); err != nil {
			log.Printf("Warning: Could not collect TLS security profiles: %v", err)
		} else {
			tlsConfig = config
		}
	}

	results := ScanResults{
		Timestamp:         startTime.Format(time.RFC3339),
		TotalIPs:          totalIPs,
		IPResults:         make([]IPResult, 0, totalIPs),
		TLSSecurityConfig: tlsConfig,
	}

	// Create a channel to send PodInfo to workers
	podChan := make(chan PodInfo, len(pods))

	// Use a WaitGroup to wait for all workers to complete
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Start worker goroutines
	for w := 0; w < concurrentScans; w++ {
		workerID := w + 1
		log.Printf("Starting WORKER %d", workerID)
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for pod := range podChan {
				log.Printf("WORKER %d: Processing Pod %s/%s", workerID, pod.Namespace, pod.Name)

				component, err := k8sClient.getOpenshiftComponentFromImage(pod.Image)
				if err != nil {
					log.Printf("Could not get openshift component for image %s: %v", pod.Image, err)
				}

				for _, ip := range pod.IPs {
					ipResult := scanIP(k8sClient, ip, pod, tlsConfig, concurrentScans)
					ipResult.OpenshiftComponent = component

					mu.Lock()
					results.IPResults = append(results.IPResults, ipResult)
					results.ScannedIPs++
					mu.Unlock()
					log.Printf("WORKER %d: Completed %s (%d/%d IPs done)", workerID, ip, results.ScannedIPs, totalIPs)
				}
			}
			log.Printf("WORKER %d: FINISHED", workerID)
		}(workerID)
	}

	// Send PodInfo to workers
	for _, pod := range pods {
		podChan <- pod
	}
	close(podChan)

	// Wait for all workers to complete
	wg.Wait()

	duration := time.Since(startTime)

	fmt.Printf("\n========================================\n")
	fmt.Printf("CONCURRENT CLUSTER SCAN COMPLETE!\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total IPs processed: %d\n", results.ScannedIPs)
	fmt.Printf("Total time: %v\n", duration)
	fmt.Printf("Concurrent workers used: %d\n", concurrentScans)
	fmt.Printf("Average time per IP: %.2fs\n", duration.Seconds()/float64(results.ScannedIPs))
	fmt.Printf("========================================\n")

	return results
}

func writeTargetsFile(targets []string) (string, error) {
	f, err := os.CreateTemp("", "testssl-targets-*.txt")
	if err != nil {
		return "", err
	}
	for _, t := range targets {
		fmt.Fprintln(f, t)
	}
	f.Close()
	return f.Name(), nil
}

// groupTestSSLOutputByPort splits a combined testssl.sh JSON output (from --file mode)
// into per-port JSON blobs keyed by port string.
func groupTestSSLOutputByPort(jsonData []byte) (map[string][]byte, error) {
	var rawData []map[string]interface{}
	if err := json.Unmarshal(jsonData, &rawData); err != nil {
		return nil, err
	}

	grouped := make(map[string][]map[string]interface{})
	for _, finding := range rawData {
		port, _ := finding["port"].(string)
		if port == "" {
			continue
		}
		grouped[port] = append(grouped[port], finding)
	}

	result := make(map[string][]byte)
	for port, findings := range grouped {
		data, err := json.Marshal(findings)
		if err != nil {
			continue
		}
		result[port] = data
	}
	return result, nil
}

// groupTestSSLOutputByIPPort splits a combined testssl.sh JSON output (from --file mode)
// into per-target groups keyed by "ip:port". Used when targets span multiple IPs.
func groupTestSSLOutputByIPPort(jsonData []byte) (map[string][]map[string]interface{}, error) {
	var rawData []map[string]interface{}
	if err := json.Unmarshal(jsonData, &rawData); err != nil {
		return nil, err
	}

	grouped := make(map[string][]map[string]interface{})
	for _, finding := range rawData {
		ip, _ := finding["ip"].(string)
		port, _ := finding["port"].(string)
		if ip == "" || port == "" {
			continue
		}
		key := ip + ":" + port
		grouped[key] = append(grouped[key], finding)
	}

	return grouped, nil
}

func scanIP(k8sClient *K8sClient, ip string, pod PodInfo, tlsSecurityProfile *TLSSecurityProfile, concurrentScans int) IPResult {
	defer timings.Track("scanIP", ip)()
	openPorts, err := discoverPortsFromPodSpec(pod.Pod)
	if err != nil {
		return IPResult{
			IP:     ip,
			Pod:    &pod,
			Status: "error",
			Error:  fmt.Sprintf("port discovery failed: %v", err),
		}
	}

	if len(openPorts) == 0 {
		return IPResult{
			IP:        ip,
			Pod:       &pod,
			Status:    "scanned",
			OpenPorts: []int{},
			PortResults: []PortResult{{
				Port:   0,
				Status: StatusNoPorts,
				Reason: "Pod declares no TCP ports in spec",
			}},
		}
	}

	// Run lsof BEFORE scanning to get listen address information
	if k8sClient != nil && len(pod.Containers) > 0 {
		k8sClient.getAndCachePodProcesses(pod)
	}

	ipResult := IPResult{
		IP:          ip,
		Pod:         &pod,
		Status:      "scanned",
		OpenPorts:   openPorts,
		PortResults: make([]PortResult, 0, len(openPorts)),
	}

	// Check for localhost-only ports and filter them out before TLS scan
	var portsToScan []int
	localhostOnlyPorts := make(map[int]string) // port -> listen address

	for _, port := range openPorts {
		if k8sClient != nil {
			if isLocalhost, listenAddr := k8sClient.isLocalhostOnly(ip, port); isLocalhost {
				localhostOnlyPorts[port] = listenAddr
				log.Printf("Port %d on %s is bound to localhost only (%s), skipping network scan", port, ip, listenAddr)
				continue
			}
		}
		portsToScan = append(portsToScan, port)
	}

	// Add localhost-only ports to results immediately
	for port, listenAddr := range localhostOnlyPorts {
		portResult := PortResult{
			Port:          port,
			Protocol:      "tcp",
			State:         "localhost",
			Status:        StatusLocalhostOnly,
			Reason:        fmt.Sprintf("Bound to %s, not accessible from pod IP", listenAddr),
			ListenAddress: listenAddr,
		}
		// Get process name if available
		if k8sClient != nil {
			k8sClient.processCacheMutex.Lock()
			if processName, ok := k8sClient.processNameMap[ip][port]; ok {
				portResult.ProcessName = processName
				portResult.ContainerName = strings.Join(pod.Containers, ",")
			}
			k8sClient.processCacheMutex.Unlock()
		}
		ipResult.PortResults = append(ipResult.PortResults, portResult)
	}

	// If no ports to scan via network, return early
	if len(portsToScan) == 0 {
		log.Printf("All ports for %s are localhost-only, no network scan needed", ip)
		return ipResult
	}

	// Batch scan all ports in a single testssl.sh --file invocation
	log.Printf("Scanning %d ports on %s with testssl.sh --file batch mode", len(portsToScan), ip)

	var targets []string
	for _, port := range portsToScan {
		targets = append(targets, fmt.Sprintf("%s:%d", ip, port))
	}

	targetsFileName, err := writeTargetsFile(targets)
	if err != nil {
		log.Printf("Failed to create targets file for %s: %v", ip, err)
		return ipResult
	}
	defer os.Remove(targetsFileName)

	outputFile, err := os.CreateTemp("", fmt.Sprintf("testssl-%s-batch-*.json", ip))
	if err != nil {
		log.Printf("Failed to create output file for %s: %v", ip, err)
		return ipResult
	}
	outputFileName := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputFileName)

	cmd := exec.Command("testssl.sh", "--file", targetsFileName, "--jsonfile", outputFileName, "--warnings", "off", "--quiet", "--color", "0", "--parallel")
	cmd.Env = append(os.Environ(), fmt.Sprintf("MAX_PARALLEL=%d", concurrentScans))
	stopTestSSL := timings.Track("testssl.sh[batch]", ip)
	cmdOutput, cmdErr := cmd.CombinedOutput()
	stopTestSSL()
	if cmdErr != nil {
		log.Printf("testssl.sh batch scan returned non-zero exit code for %s: %v (output: %s)", ip, cmdErr, string(cmdOutput))
	}

	jsonData, err := os.ReadFile(outputFileName)
	if err != nil || len(jsonData) == 0 {
		log.Printf("testssl.sh batch scan produced no output for %s: %v", ip, err)
		return ipResult
	}

	portDataMap, err := groupTestSSLOutputByPort(jsonData)
	if err != nil {
		log.Printf("Error grouping testssl.sh output by port for %s: %v", ip, err)
		return ipResult
	}

	resultsByPort := make(map[int]PortResult)
	for _, port := range portsToScan {
		portStr := strconv.Itoa(port)
		portResult := PortResult{
			Port:     port,
			Protocol: "tcp",
			State:    "open",
			Service:  "ssl/tls",
		}

		if portData, ok := portDataMap[portStr]; ok {
			scanResult := parseTestSSLOutput(portData, ip, portStr)
			portResult.TlsVersions, portResult.TlsCiphers, portResult.TlsCipherStrength = extractTLSInfo(scanResult)
		}

		if len(portResult.TlsCiphers) > 0 {
			portResult.Status = StatusOK
			portResult.Reason = "TLS scan successful"
		} else {
			portResult.Status = StatusNoTLS
			portResult.Reason = "Port open but no TLS detected"
		}

		resultsByPort[port] = portResult
	}

	// Correlate results with discovered ports
	for _, port := range portsToScan {
		if portResult, ok := resultsByPort[port]; ok {
			// Log port state for debugging
			if portResult.State == "filtered" {
				log.Printf("Port %d on %s is filtered (not accessible). This may be due to firewall rules, network policies, or the service not listening on this IP. TLS information will be N/A.", port, ip)
			} else if portResult.State != "open" {
				log.Printf("Port %d on %s has state '%s'. TLS information may be unavailable.", port, ip, portResult.State)
			}

			// Check compliance and get process info if TLS data was found
			if len(portResult.TlsCiphers) > 0 {
				log.Printf("Found TLS information for port %d on %s: %d ciphers, versions: %v", port, ip, len(portResult.TlsCiphers), portResult.TlsVersions)
				checkCompliance(&portResult, tlsSecurityProfile)

				if k8sClient != nil && len(pod.Containers) > 0 {
					k8sClient.processCacheMutex.Lock()
					if processName, ok := k8sClient.processNameMap[ip][port]; ok {
						portResult.ProcessName = processName
						portResult.ContainerName = strings.Join(pod.Containers, ",")
						log.Printf("Identified process for port %d on %s: %s", port, ip, processName)
					}
					k8sClient.processCacheMutex.Unlock()
				}
			} else {
				log.Printf("No TLS information found for port %d on %s (state: %s). This port may not be listening, may be blocked by network policies, or may not be a TLS service.", port, ip, portResult.State)
			}

			// Get listen address info if available
			if k8sClient != nil {
				if info, ok := k8sClient.getListenInfo(ip, port); ok {
					portResult.ListenAddress = info.ListenAddress
				}
			}

			ipResult.PortResults = append(ipResult.PortResults, portResult)
		} else {
			// Port was discovered but not in the ssl-enum-ciphers result (e.g., not an SSL port)
			log.Printf("Port %d on %s was declared in pod spec but not found in scan results. Assuming non-TLS service.", port, ip)
			ipResult.PortResults = append(ipResult.PortResults, PortResult{
				Port:   port,
				State:  "open",
				Status: StatusNoTLS,
				Reason: "Port open but no TLS detected (plain HTTP/TCP)",
			})
		}
	}

	return ipResult
}

// categorizePortResult determines the Status and Reason based on scan results
func categorizePortResult(portResult PortResult, tlsPort Port) (ScanStatus, string) {
	// Check if TLS was successfully detected
	if len(portResult.TlsCiphers) > 0 {
		return StatusOK, "TLS scan successful"
	}

	// Categorize based on port state
	switch portResult.State {
	case "filtered":
		return StatusFiltered, "Network policy or firewall blocking access"
	case "closed":
		return StatusClosed, "Port not listening on this IP"
	case "open":
		// Port is open but no TLS - check for specific error patterns
		// Check if it might be mTLS required (handshake failure patterns)
		for _, script := range tlsPort.Scripts {
			if script.ID == "ssl-enum-ciphers" {
				for _, elem := range script.Elems {
					if strings.Contains(strings.ToLower(elem.Value), "handshake") ||
						strings.Contains(strings.ToLower(elem.Value), "certificate") {
						return StatusMTLSRequired, "TLS handshake failed - may require client certificate"
					}
				}
			}
		}
		// Check for timeout patterns
		if tlsPort.State.Reason == "no-response" {
			return StatusTimeout, "Connection timed out"
		}
		// Default: port is open but not using TLS
		return StatusNoTLS, "Port open but no TLS detected (plain HTTP/TCP)"
	default:
		return StatusError, fmt.Sprintf("Unknown port state: %s", portResult.State)
	}
}

// limitPodsToIPCount limits the pod list to contain at most maxIPs total IP addresses
func limitPodsToIPCount(pods []PodInfo, maxIPs int) []PodInfo {
	if maxIPs <= 0 {
		return pods
	}

	var limitedPods []PodInfo
	currentIPCount := 0

	for _, pod := range pods {
		if currentIPCount >= maxIPs {
			break
		}

		// If this pod would exceed the limit, include only some of its IPs
		if currentIPCount+len(pod.IPs) > maxIPs {
			remainingIPs := maxIPs - currentIPCount
			limitedPod := pod
			limitedPod.IPs = pod.IPs[:remainingIPs]
			limitedPods = append(limitedPods, limitedPod)
			break
		}

		// Include the entire pod
		limitedPods = append(limitedPods, pod)
		currentIPCount += len(pod.IPs)
	}

	return limitedPods
}

func performTargetsScan(targetsByHost map[string][]string, concurrentScans int) ScanResults {
	defer timings.Track("performTargetsScan", "")()
	startTime := time.Now()

	totalIPs := len(targetsByHost)

	var allTargets []string
	for host, ports := range targetsByHost {
		for _, portStr := range ports {
			allTargets = append(allTargets, fmt.Sprintf("%s:%s", host, portStr))
		}
	}

	fmt.Printf("========================================\n")
	fmt.Printf("TARGETS SCAN STARTING\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total hosts to scan: %d\n", totalIPs)
	fmt.Printf("Total targets: %d\n", len(allTargets))
	fmt.Printf("MAX_PARALLEL: %d\n", concurrentScans)
	fmt.Printf("========================================\n\n")

	results := ScanResults{
		Timestamp: startTime.Format(time.RFC3339),
		TotalIPs:  totalIPs,
		IPResults: make([]IPResult, 0, totalIPs),
	}

	if len(allTargets) == 0 {
		return results
	}

	targetsFileName, err := writeTargetsFile(allTargets)
	if err != nil {
		log.Printf("Failed to create targets file: %v", err)
		return results
	}
	defer os.Remove(targetsFileName)

	outputFile, err := os.CreateTemp("", "testssl-targets-batch-*.json")
	if err != nil {
		log.Printf("Failed to create output file: %v", err)
		return results
	}
	outputFileName := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputFileName)

	log.Printf("Running testssl.sh --file batch scan on %d targets across %d hosts", len(allTargets), totalIPs)
	cmd := exec.Command("testssl.sh", "-p", "-s", "-f", "--file", targetsFileName, "--jsonfile", outputFileName, "--warnings", "off", "--quiet", "--color", "0", "--parallel")
	cmd.Env = append(os.Environ(), fmt.Sprintf("MAX_PARALLEL=%d", concurrentScans))
	stopTestSSL := timings.Track("testssl.sh[batch]", fmt.Sprintf("%d targets", len(allTargets)))
	cmdOutput, cmdErr := cmd.CombinedOutput()
	stopTestSSL()
	if cmdErr != nil {
		log.Printf("testssl.sh batch scan returned non-zero exit code: %v (output: %s)", cmdErr, string(cmdOutput))
	}

	jsonData, readErr := os.ReadFile(outputFileName)
	if readErr != nil || len(jsonData) == 0 {
		log.Printf("testssl.sh batch scan produced no output: %v", readErr)
		return results
	}

	grouped, groupErr := groupTestSSLOutputByIPPort(jsonData)
	if groupErr != nil {
		log.Printf("Error grouping testssl.sh output: %v", groupErr)
		return results
	}

	for host, ports := range targetsByHost {
		ipResult := IPResult{
			IP:          host,
			Status:      "scanned",
			PortResults: make([]PortResult, 0, len(ports)),
		}
		for _, pStr := range ports {
			p, _ := strconv.Atoi(pStr)
			ipResult.OpenPorts = append(ipResult.OpenPorts, p)
		}

		for _, portStr := range ports {
			port, _ := strconv.Atoi(portStr)
			portResult := PortResult{
				Port:     port,
				Protocol: "tcp",
				State:    "open",
				Service:  "ssl/tls",
			}

			key := host + ":" + portStr
			if findings, ok := grouped[key]; ok {
				portData, _ := json.Marshal(findings)
				scanResult := parseTestSSLOutput(portData, host, portStr)
				portResult.TlsVersions, portResult.TlsCiphers, portResult.TlsCipherStrength = extractTLSInfo(scanResult)
				portResult.TlsKeyExchange = extractKeyExchangeFromTestSSL(portData)
			}

			if len(portResult.TlsCiphers) > 0 {
				portResult.Status = StatusOK
				portResult.Reason = "TLS scan successful"
			} else {
				portResult.Status = StatusNoTLS
				portResult.Reason = "Port open but no TLS detected"
			}

			ipResult.PortResults = append(ipResult.PortResults, portResult)
		}

		results.IPResults = append(results.IPResults, ipResult)
		results.ScannedIPs++
	}

	duration := time.Since(startTime)

	fmt.Printf("\n========================================\n")
	fmt.Printf("TARGETS SCAN COMPLETE!\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total hosts processed: %d\n", results.ScannedIPs)
	fmt.Printf("Total time: %v\n", duration)
	fmt.Printf("MAX_PARALLEL used: %d\n", concurrentScans)
	if results.ScannedIPs > 0 {
		fmt.Printf("Average time per host: %.2fs\n", duration.Seconds()/float64(results.ScannedIPs))
	}
	fmt.Printf("========================================\n")

	return results
}

func scanHostPorts(host string, ports []string, concurrentScans int) IPResult {
	defer timings.Track("scanHostPorts", host)()
	log.Printf("Scanning TLS on %s for ports: %s", host, strings.Join(ports, ","))

	ipResult := IPResult{
		IP:          host,
		Status:      "scanned",
		PortResults: make([]PortResult, 0, len(ports)),
	}
	for _, pStr := range ports {
		p, _ := strconv.Atoi(pStr)
		ipResult.OpenPorts = append(ipResult.OpenPorts, p)
	}

	// Batch scan all ports in a single testssl.sh --file invocation
	var targets []string
	for _, portStr := range ports {
		targets = append(targets, fmt.Sprintf("%s:%s", host, portStr))
	}

	targetsFileName, err := writeTargetsFile(targets)
	if err != nil {
		log.Printf("Failed to create targets file for %s: %v", host, err)
		return ipResult
	}
	defer os.Remove(targetsFileName)

	outputFile, err := os.CreateTemp("", fmt.Sprintf("testssl-%s-batch-*.json", host))
	if err != nil {
		log.Printf("Failed to create output file for %s: %v", host, err)
		return ipResult
	}
	outputFileName := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputFileName)

	log.Printf("Running testssl.sh --file batch scan on %s for %d ports", host, len(ports))
	cmd := exec.Command("testssl.sh", "--file", targetsFileName, "--jsonfile", outputFileName, "--warnings", "off", "--quiet", "--color", "0", "--parallel")
	cmd.Env = append(os.Environ(), fmt.Sprintf("MAX_PARALLEL=%d", concurrentScans))
	stopTestSSL := timings.Track("testssl.sh[batch]", host)
	cmdOutput, cmdErr := cmd.CombinedOutput()
	stopTestSSL()
	if cmdErr != nil {
		log.Printf("testssl.sh batch scan returned non-zero exit code for %s: %v (output: %s)", host, cmdErr, string(cmdOutput))
	}

	jsonData, readErr := os.ReadFile(outputFileName)
	if readErr != nil || len(jsonData) == 0 {
		log.Printf("testssl.sh batch scan produced no output for %s: %v", host, readErr)
		return ipResult
	}

	portDataMap, groupErr := groupTestSSLOutputByPort(jsonData)
	if groupErr != nil {
		log.Printf("Error grouping testssl.sh output by port for %s: %v", host, groupErr)
		return ipResult
	}

	resultsByPort := make(map[int]PortResult)
	for _, portStr := range ports {
		port, _ := strconv.Atoi(portStr)
		portResult := PortResult{
			Port:     port,
			Protocol: "tcp",
			State:    "open",
			Service:  "ssl/tls",
		}

		if portData, ok := portDataMap[portStr]; ok {
			scanResult := parseTestSSLOutput(portData, host, portStr)
			portResult.TlsVersions, portResult.TlsCiphers, portResult.TlsCipherStrength = extractTLSInfo(scanResult)
			portResult.TlsKeyExchange = extractKeyExchangeFromTestSSL(portData)
		}

		if len(portResult.TlsCiphers) > 0 {
			portResult.Status = StatusOK
			portResult.Reason = "TLS scan successful"
		} else {
			portResult.Status = StatusNoTLS
			portResult.Reason = "Port open but no TLS detected"
		}

		resultsByPort[port] = portResult
	}

	for _, portStr := range ports {
		port, _ := strconv.Atoi(portStr)
		if portResult, ok := resultsByPort[port]; ok {
			ipResult.PortResults = append(ipResult.PortResults, portResult)
		} else {
			// Port was specified but not in the result (e.g., not an SSL port or closed)
			ipResult.PortResults = append(ipResult.PortResults, PortResult{
				Port:   port,
				State:  "closed/filtered",
				Status: StatusClosed,
				Reason: "Port not responding or filtered",
			})
		}
	}

	return ipResult
}

// parseTestSSLOutput parses testssl.sh JSON output and converts to ScanRun format for compatibility
func parseTestSSLOutput(jsonData []byte, host, port string) ScanRun {
	var rawData []map[string]interface{}

	if err := json.Unmarshal(jsonData, &rawData); err != nil {
		log.Printf("Error parsing testssl.sh JSON output: %v", err)
		return ScanRun{Hosts: []Host{{
			Ports: []Port{{
				PortID:   port,
				Protocol: "tcp",
				State:    State{State: "open"},
				Service:  Service{Name: "ssl/tls"},
			}},
		}}}
	}

	return convertTestSSLToScanRun(rawData, host, port)
}

// parseTestSSLOutputFromFile reads and parses testssl.sh JSON output from a file
func parseTestSSLOutputFromFile(filename, host, port string) ScanRun {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Error reading testssl.sh output file %s: %v", filename, err)
		return ScanRun{Hosts: []Host{{
			Ports: []Port{{
				PortID:   port,
				Protocol: "tcp",
				State:    State{State: "open"},
				Service:  Service{Name: "ssl/tls"},
			}},
		}}}
	}

	return parseTestSSLOutput(data, host, port)
}

// convertTestSSLToScanRun converts testssl.sh JSON format to ScanRun format
func convertTestSSLToScanRun(rawData []map[string]interface{}, host, port string) ScanRun {
	scanResult := ScanRun{
		Hosts: []Host{{
			Status: Status{State: "up"},
			Ports: []Port{{
				PortID:   port,
				Protocol: "tcp",
				State:    State{State: "open"},
				Service:  Service{Name: "ssl/tls"},
				Scripts:  []Script{},
			}},
		}},
	}

	tlsScript := Script{
		ID:     "ssl-enum-ciphers",
		Tables: []Table{},
	}

	tlsVersions := make(map[string][]Table)
	detectedVersions := make(map[string]bool)

	for _, finding := range rawData {
		id, _ := finding["id"].(string)
		findingValue, _ := finding["finding"].(string)
		severity, _ := finding["severity"].(string)

		if findingValue == "" || findingValue == "not offered" {
			continue
		}

		if isProtocolID(id) {
			versionName := extractTLSVersion(id)
			if versionName != "" && strings.HasPrefix(findingValue, "offered") {
				detectedVersions[versionName] = true
				if _, exists := tlsVersions[versionName]; !exists {
					tlsVersions[versionName] = []Table{}
				}
			}
		}

		// Match actual cipher entries like "cipher-tls1_2_xc02b" but NOT metadata entries
		// Exclude: cipher_order-*, cipherlist_*, cipherorder_*, cipher_strength_score*, etc.
		isCipherEntry := (strings.HasPrefix(id, "cipher-") || strings.HasPrefix(id, "cipher_")) &&
			!strings.Contains(id, "order") &&
			!strings.Contains(id, "list") &&
			!strings.Contains(id, "score")
		if isCipherEntry {
			cipherName := extractCipherName(findingValue)
			if cipherName == "" {
				cipherName = strings.TrimPrefix(id, "cipher-")
				cipherName = strings.TrimPrefix(cipherName, "cipher_")
			}

			versionName := extractTLSVersionFromCipherID(id, finding)

			if versionName != "" {
				detectedVersions[versionName] = true
				if _, exists := tlsVersions[versionName]; !exists {
					tlsVersions[versionName] = []Table{}
				}

				cipherTable := Table{
					Key: "",
					Elems: []Elem{
						{Key: "name", Value: cipherName},
						{Key: "strength", Value: mapSeverityToStrength(severity)},
					},
				}
				tlsVersions[versionName] = append(tlsVersions[versionName], cipherTable)
			}
		}
	}

	for version := range detectedVersions {
		ciphers := tlsVersions[version]

		versionTable := Table{
			Key:    version,
			Tables: []Table{},
			Elems:  []Elem{},
		}

		if len(ciphers) > 0 {
			ciphersTable := Table{
				Key:    "ciphers",
				Tables: ciphers,
				Elems:  []Elem{},
			}
			versionTable.Tables = append(versionTable.Tables, ciphersTable)
		}

		tlsScript.Tables = append(tlsScript.Tables, versionTable)
	}

	scanResult.Hosts[0].Ports[0].Scripts = append(scanResult.Hosts[0].Ports[0].Scripts, tlsScript)

	return scanResult
}

func extractCipherName(finding string) string {
	parts := strings.Fields(finding)
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return ""
}

func isProtocolID(id string) bool {
	lower := strings.ToLower(id)
	return strings.HasPrefix(lower, "tls") || strings.HasPrefix(lower, "ssl")
}

func extractTLSVersion(id string) string {
	lower := strings.ToLower(id)
	switch {
	case strings.Contains(lower, "tls1_3"):
		return "TLSv1.3"
	case strings.Contains(lower, "tls1_2"):
		return "TLSv1.2"
	case strings.Contains(lower, "tls1_1"):
		return "TLSv1.1"
	case strings.Contains(lower, "tls1"):
		return "TLSv1.0"
	case strings.Contains(lower, "ssl3") || strings.Contains(lower, "sslv3"):
		return "SSLv3"
	case strings.Contains(lower, "ssl2") || strings.Contains(lower, "sslv2"):
		return "SSLv2"
	default:
		return ""
	}
}

func extractTLSVersionFromCipherID(id string, finding map[string]interface{}) string {
	if strings.Contains(id, "tls1_3") {
		return "TLSv1.3"
	}
	if strings.Contains(id, "tls1_2") {
		return "TLSv1.2"
	}
	if strings.Contains(id, "tls1_1") {
		return "TLSv1.1"
	}
	if strings.Contains(id, "tls1_0") || strings.Contains(id, "tls1-") {
		return "TLSv1.0"
	}
	if strings.Contains(id, "ssl3") {
		return "SSLv3"
	}
	if strings.Contains(id, "ssl2") {
		return "SSLv2"
	}

	if section, ok := finding["section"].(string); ok {
		ver := extractTLSVersion(section)
		if ver != "" {
			return ver
		}
	}

	findingValue, _ := finding["finding"].(string)
	if strings.Contains(findingValue, "TLS_AES_") || strings.Contains(findingValue, "TLS_CHACHA20_") {
		return "TLSv1.3"
	}

	return "TLSv1.2"
}

func mapSeverityToStrength(severity string) string {
	switch severity {
	case "OK", "LOW":
		return "A"
	case "MEDIUM":
		return "B"
	case "HIGH":
		return "C"
	case "CRITICAL":
		return "F"
	default:
		return "unknown"
	}
}

// extractKeyExchangeFromTestSSL extracts forward secrecy and KEM information from testssl.sh raw JSON output
func extractKeyExchangeFromTestSSL(jsonData []byte) *KeyExchangeInfo {
	var rawData []map[string]interface{}
	if err := json.Unmarshal(jsonData, &rawData); err != nil {
		log.Printf("Error parsing testssl.sh JSON for key exchange: %v", err)
		return nil
	}

	keyExchange := &KeyExchangeInfo{
		Groups:         []string{},
		ForwardSecrecy: &ForwardSecrecy{},
	}

	var ecdheCiphers []string
	var kemGroups []string
	var allGroups []string

	for _, finding := range rawData {
		id, _ := finding["id"].(string)
		findingValue, _ := finding["finding"].(string)

		if findingValue == "" || findingValue == "not offered" || findingValue == "not supported" {
			continue
		}

		switch {
		case id == "FS":
			keyExchange.ForwardSecrecy.Supported = strings.Contains(strings.ToLower(findingValue), "offered") ||
				strings.Contains(strings.ToLower(findingValue), "yes") ||
				strings.Contains(strings.ToLower(findingValue), "ok")

		case id == "FS_ECDHE" || id == "FS_ciphers":
			parts := strings.Fields(findingValue)
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" && !stringInSlice(p, ecdheCiphers) {
					ecdheCiphers = append(ecdheCiphers, p)
				}
			}

		case id == "FS_KEMs" || strings.HasPrefix(id, "FS_KEM"):
			parts := strings.Fields(findingValue)
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" && !stringInSlice(p, kemGroups) {
					kemGroups = append(kemGroups, p)
				}
			}

		// Supported groups / named curves (includes both classical and post-quantum)
		case id == "supported_groups" || id == "named_groups" || id == "curves":
			// Parse supported key exchange groups
			// Format: "x25519 secp256r1 secp384r1 X25519MLKEM768 ..."
			parts := strings.Fields(findingValue)
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" && !stringInSlice(p, allGroups) {
					allGroups = append(allGroups, p)
					// Categorize as KEM if it contains MLKEM or KEM
					if isKEMGroup(p) && !stringInSlice(p, kemGroups) {
						kemGroups = append(kemGroups, p)
					}
				}
			}

		// Individual group/curve findings
		case strings.HasPrefix(id, "group_") || strings.HasPrefix(id, "curve_"):
			groupName := strings.TrimPrefix(id, "group_")
			groupName = strings.TrimPrefix(groupName, "curve_")
			if findingValue == "offered" || findingValue == "yes" || strings.Contains(strings.ToLower(findingValue), "supported") {
				if !stringInSlice(groupName, allGroups) {
					allGroups = append(allGroups, groupName)
				}
				if isKEMGroup(groupName) && !stringInSlice(groupName, kemGroups) {
					kemGroups = append(kemGroups, groupName)
				}
			}
		}
	}

	keyExchange.Groups = allGroups
	keyExchange.ForwardSecrecy.ECDHE = ecdheCiphers
	keyExchange.ForwardSecrecy.KEMs = kemGroups

	// If we found KEM groups, mark forward secrecy as supported
	if len(kemGroups) > 0 {
		keyExchange.ForwardSecrecy.Supported = true
	}

	// Return nil if no meaningful data was found
	if len(allGroups) == 0 && len(ecdheCiphers) == 0 && len(kemGroups) == 0 && !keyExchange.ForwardSecrecy.Supported {
		return nil
	}

	return keyExchange
}

// isKEMGroup returns true if the group name indicates a KEM (Key Encapsulation Mechanism)
func isKEMGroup(name string) bool {
	name = strings.ToLower(name)
	return strings.Contains(name, "mlkem") ||
		strings.Contains(name, "ml-kem") ||
		strings.Contains(name, "kyber") ||
		strings.Contains(name, "kem") ||
		strings.Contains(name, "sntrup") || // NTRU-based
		strings.Contains(name, "bike") || // BIKE KEM
		strings.Contains(name, "hqc") // HQC KEM
}

// readTestSSLJSONFile reads raw JSON data from a testssl.sh output file
func readTestSSLJSONFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

func hasPQCComplianceFailures(results ScanResults) bool {
	for _, ipResult := range results.IPResults {
		for _, portResult := range ipResult.PortResults {
			if portResult.Status == StatusNoPorts {
				continue
			}

			if !portResult.TLS13Supported {
				log.Printf("PQC compliance failure: %s:%d - TLS 1.3 not supported", ipResult.IP, portResult.Port)
				return true
			}

			if !portResult.MLKEMSupported {
				log.Printf("PQC compliance failure: %s:%d - ML-KEM not supported (no x25519mlkem768 or mlkem768)", ipResult.IP, portResult.Port)
				return true
			}

			hasValidMLKEM := false
			for _, kem := range portResult.MLKEMCiphers {
				kemLower := strings.ToLower(kem)
				if strings.Contains(kemLower, "x25519mlkem768") || strings.Contains(kemLower, "mlkem768") {
					hasValidMLKEM = true
					break
				}
			}
			if !hasValidMLKEM {
				log.Printf("PQC compliance failure: %s:%d - No valid ML-KEM KEM found (need x25519mlkem768 or mlkem768)", ipResult.IP, portResult.Port)
				return true
			}
		}
	}
	return false
}

func performPQCScan(targets []string, concurrentScans int) ScanResults {
	defer timings.Track("performPQCScan", "")()
	startTime := time.Now()

	fmt.Printf("========================================\n")
	fmt.Printf("PQC CHECK: TLS 1.3 + ML-KEM SCAN\n")
	fmt.Printf("========================================\n")
	fmt.Printf("TLS Version: testssl.sh -p (protocols only)\n")
	fmt.Printf("ML-KEM:      testssl.sh -f (KEMs offered)\n")
	fmt.Printf("Targets:     %d\n", len(targets))
	fmt.Printf("Parallel:    %d\n", concurrentScans)
	fmt.Printf("========================================\n\n")

	results := ScanResults{
		Timestamp: startTime.Format(time.RFC3339),
		TotalIPs:  len(targets),
		IPResults: make([]IPResult, 0, len(targets)),
	}

	if len(targets) == 0 {
		return results
	}

	targetsFileName, err := writeTargetsFile(targets)
	if err != nil {
		log.Printf("Failed to create targets file for PQC scan: %v", err)
		return results
	}
	defer os.Remove(targetsFileName)

	outputFile, err := os.CreateTemp("", "testssl-pqc-batch-*.json")
	if err != nil {
		log.Printf("Failed to create output file for PQC scan: %v", err)
		return results
	}
	outputFileName := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputFileName)

	log.Printf("PQC batch check on %d targets", len(targets))

	cmd := exec.Command("testssl.sh", "-p", "-f", "--file", targetsFileName, "--jsonfile", outputFileName, "--quiet", "--color", "0", "--ip", "one", "--parallel")
	cmd.Env = append(os.Environ(), fmt.Sprintf("MAX_PARALLEL=%d", concurrentScans))
	stopTestSSL := timings.Track("testssl.sh[pqc-batch]", fmt.Sprintf("%d targets", len(targets)))
	cmdOutput, cmdErr := cmd.CombinedOutput()
	stopTestSSL()
	if cmdErr != nil {
		log.Printf("testssl.sh PQC batch scan returned non-zero exit code: %v (output: %s)", cmdErr, string(cmdOutput))
	}

	jsonData, err := os.ReadFile(outputFileName)
	if err != nil || len(jsonData) == 0 {
		log.Printf("testssl.sh PQC batch scan produced no output: %v", err)
		return results
	}

	grouped, err := groupTestSSLOutputByIPPort(jsonData)
	if err != nil {
		log.Printf("Error grouping PQC output: %v", err)
		return results
	}

	for _, target := range targets {
		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			results.IPResults = append(results.IPResults, IPResult{
				IP:     target,
				Status: "error",
				Error:  fmt.Sprintf("Invalid target: %v", err),
			})
			results.ScannedIPs++
			continue
		}

		port, _ := strconv.Atoi(portStr)

		portResult := PortResult{
			Port:     port,
			Protocol: "tcp",
			State:    "open",
			Service:  "https",
			Status:   StatusOK,
		}

		findings := grouped[host+":"+portStr]
		if findings != nil {
			tls13, tlsVersions, mlkemSupported, mlkemKEMs, allKEMs := parsePQCFindings(findings)
			portResult.TlsVersions = tlsVersions
			portResult.TLS13Supported = tls13
			portResult.MLKEMSupported = mlkemSupported
			portResult.MLKEMCiphers = mlkemKEMs
			portResult.AllKEMs = allKEMs

			if tls13 && mlkemSupported {
				portResult.Reason = "TLS 1.3 + ML-KEM supported (PQC ready)"
			} else if tls13 {
				portResult.Reason = "TLS 1.3 supported, ML-KEM not available"
			} else {
				portResult.Reason = "TLS 1.3 not supported"
			}
		} else {
			portResult.Reason = "Could not determine TLS support"
			portResult.Status = StatusNoTLS
		}

		results.IPResults = append(results.IPResults, IPResult{
			IP:          host,
			Status:      "scanned",
			OpenPorts:   []int{port},
			PortResults: []PortResult{portResult},
		})
		results.ScannedIPs++
	}

	return results
}

func performPQCClusterScan(pods []PodInfo, k8sClient *K8sClient, concurrentScans int) ScanResults {
	defer timings.Track("performPQCClusterScan", "")()
	startTime := time.Now()

	fmt.Printf("========================================\n")
	fmt.Printf("PQC CLUSTER CHECK: TLS 1.3 + ML-KEM SCAN\n")
	fmt.Printf("========================================\n")
	fmt.Printf("TLS Version: testssl.sh -p (protocols only)\n")
	fmt.Printf("ML-KEM:      testssl.sh -f (KEMs offered)\n")
	fmt.Printf("Pods:        %d\n", len(pods))
	fmt.Printf("Parallel:    %d\n", concurrentScans)
	fmt.Printf("========================================\n\n")

	results := ScanResults{
		Timestamp: startTime.Format(time.RFC3339),
		TotalIPs:  len(pods),
		IPResults: make([]IPResult, 0, len(pods)),
	}

	if len(pods) == 0 {
		return results
	}

	type podMeta struct {
		pod       PodInfo
		component *OpenshiftComponent
		ip        string
		ports     []int
	}

	var allTargets []string
	podMetas := make([]podMeta, 0, len(pods))

	for _, pod := range pods {
		ip := ""
		if len(pod.IPs) > 0 {
			ip = pod.IPs[0]
		}

		ports, _ := discoverPortsFromPodSpec(pod.Pod)

		var component *OpenshiftComponent
		if k8sClient != nil {
			component, _ = k8sClient.getOpenshiftComponentFromImage(pod.Image)
		}

		pm := podMeta{pod: pod, component: component, ip: ip, ports: ports}
		podMetas = append(podMetas, pm)

		for _, port := range ports {
			allTargets = append(allTargets, fmt.Sprintf("%s:%d", ip, port))
		}
	}

	var grouped map[string][]map[string]interface{}

	if len(allTargets) > 0 {
		targetsFileName, err := writeTargetsFile(allTargets)
		if err != nil {
			log.Printf("Failed to create targets file for PQC cluster scan: %v", err)
			return results
		}
		defer os.Remove(targetsFileName)

		outputFile, err := os.CreateTemp("", "testssl-pqc-cluster-*.json")
		if err != nil {
			log.Printf("Failed to create output file for PQC cluster scan: %v", err)
			return results
		}
		outputFileName := outputFile.Name()
		outputFile.Close()
		defer os.Remove(outputFileName)

		log.Printf("PQC cluster batch check on %d targets across %d pods", len(allTargets), len(pods))

		cmd := exec.Command("testssl.sh", "-p", "-f", "--file", targetsFileName, "--jsonfile", outputFileName, "--quiet", "--color", "0", "--ip", "one", "--parallel")
		cmd.Env = append(os.Environ(), fmt.Sprintf("MAX_PARALLEL=%d", concurrentScans))
		stopTestSSL := timings.Track("testssl.sh[pqc-cluster-batch]", fmt.Sprintf("%d targets", len(allTargets)))
		cmdOutput, cmdErr := cmd.CombinedOutput()
		stopTestSSL()
		if cmdErr != nil {
			log.Printf("testssl.sh PQC cluster batch scan returned non-zero: %v (output: %s)", cmdErr, string(cmdOutput))
		}

		jsonData, err := os.ReadFile(outputFileName)
		if err == nil && len(jsonData) > 0 {
			grouped, err = groupTestSSLOutputByIPPort(jsonData)
			if err != nil {
				log.Printf("Error grouping PQC cluster output: %v", err)
			}
		} else {
			log.Printf("testssl.sh PQC cluster batch scan produced no output: %v", err)
		}
	}

	for _, pm := range podMetas {
		ipResult := IPResult{
			IP:                 pm.ip,
			Pod:                &pm.pod,
			OpenshiftComponent: pm.component,
			Status:             "scanned",
			OpenPorts:          pm.ports,
			PortResults:        make([]PortResult, 0),
		}

		if len(pm.ports) == 0 {
			ipResult.PortResults = append(ipResult.PortResults, PortResult{
				Status: StatusNoPorts,
				Reason: "Pod declares no TCP ports",
			})
		} else {
			for _, port := range pm.ports {
				portStr := strconv.Itoa(port)
				portResult := PortResult{
					Port:     port,
					Protocol: "tcp",
					State:    "open",
					Status:   StatusOK,
				}

				findings := grouped[pm.ip+":"+portStr]
				if findings != nil {
					tls13, tlsVersions, mlkemSupported, mlkemKEMs, allKEMs := parsePQCFindings(findings)
					portResult.TlsVersions = tlsVersions
					portResult.TLS13Supported = tls13
					portResult.MLKEMSupported = mlkemSupported
					portResult.MLKEMCiphers = mlkemKEMs
					portResult.AllKEMs = allKEMs

					if tls13 && mlkemSupported {
						portResult.Reason = "TLS 1.3 + ML-KEM supported (PQC ready)"
					} else if tls13 {
						portResult.Reason = "TLS 1.3 supported, ML-KEM not available"
					} else if len(tlsVersions) > 0 {
						portResult.Reason = "TLS supported, TLS 1.3 not available"
					} else {
						portResult.Reason = "Could not determine TLS support"
						portResult.Status = StatusNoTLS
					}
				} else {
					portResult.Reason = "Could not determine TLS support"
					portResult.Status = StatusNoTLS
				}

				ipResult.PortResults = append(ipResult.PortResults, portResult)
			}
		}

		results.IPResults = append(results.IPResults, ipResult)
		results.ScannedIPs++
	}

	return results
}

func parsePQCFindings(findings []map[string]interface{}) (tls13 bool, tlsVersions []string, mlkemSupported bool, mlkemKEMs []string, allKEMs []string) {
	for _, f := range findings {
		id, _ := f["id"].(string)
		finding, _ := f["finding"].(string)

		if finding == "" || finding == "not offered" || finding == "not supported" {
			continue
		}

		if isProtocolID(id) {
			version := extractTLSVersion(id)
			if version != "" && strings.HasPrefix(finding, "offered") {
				if !stringInSlice(version, tlsVersions) {
					tlsVersions = append(tlsVersions, version)
				}
				if version == "TLSv1.3" {
					tls13 = true
				}
			}
		}

		if id == "FS_KEMs" || strings.HasPrefix(id, "FS_KEM") {
			for _, g := range strings.Fields(finding) {
				if !stringInSlice(g, allKEMs) {
					allKEMs = append(allKEMs, g)
				}
				if isKEMGroup(g) && !stringInSlice(g, mlkemKEMs) {
					mlkemKEMs = append(mlkemKEMs, g)
					mlkemSupported = true
				}
			}
		}

		if id == "supported_groups" || id == "named_groups" || id == "curves" {
			for _, g := range strings.Fields(finding) {
				if !stringInSlice(g, allKEMs) {
					allKEMs = append(allKEMs, g)
				}
				if isKEMGroup(g) && !stringInSlice(g, mlkemKEMs) {
					mlkemKEMs = append(mlkemKEMs, g)
					mlkemSupported = true
				}
			}
		}

		if strings.HasPrefix(id, "group_") || strings.HasPrefix(id, "curve_") {
			groupName := strings.TrimPrefix(id, "group_")
			groupName = strings.TrimPrefix(groupName, "curve_")
			if finding == "offered" || finding == "yes" || strings.Contains(strings.ToLower(finding), "supported") {
				if !stringInSlice(groupName, allKEMs) {
					allKEMs = append(allKEMs, groupName)
				}
				if isKEMGroup(groupName) && !stringInSlice(groupName, mlkemKEMs) {
					mlkemKEMs = append(mlkemKEMs, groupName)
					mlkemSupported = true
				}
			}
		}
	}

	return
}

func printPQCClusterResults(results ScanResults) {
	fmt.Printf("\n========================================\n")
	fmt.Printf("PQC CHECK RESULTS\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Timestamp: %s\n", results.Timestamp)
	fmt.Printf("Total IPs: %d\n", results.TotalIPs)
	fmt.Printf("Scanned:   %d\n", results.ScannedIPs)
	fmt.Printf("\n")

	tls13Count := 0
	mlkemCount := 0
	pqcReadyCount := 0

	for _, ipResult := range results.IPResults {
		fmt.Printf("-----------------------------------------------------\n")
		fmt.Printf("IP: %s\n", ipResult.IP)

		if ipResult.Pod != nil {
			fmt.Printf("Pod: %s/%s\n", ipResult.Pod.Namespace, ipResult.Pod.Name)
		}
		if ipResult.OpenshiftComponent != nil {
			fmt.Printf("Component: %s\n", ipResult.OpenshiftComponent.Component)
		}

		if ipResult.Error != "" {
			fmt.Printf("  Error: %s\n", ipResult.Error)
			continue
		}

		for _, portResult := range ipResult.PortResults {
			if portResult.Status == StatusNoPorts {
				fmt.Printf("  No TCP ports declared\n")
				continue
			}

			fmt.Printf("  Port %d:\n", portResult.Port)

			if portResult.TLS13Supported {
				fmt.Printf("    TLS 1.3:  SUPPORTED\n")
				tls13Count++
			} else {
				fmt.Printf("    TLS 1.3:  NOT SUPPORTED\n")
			}

			if portResult.MLKEMSupported {
				fmt.Printf("    ML-KEM:   SUPPORTED\n")
				fmt.Printf("    ML-KEM KEMs: %s\n", strings.Join(portResult.MLKEMCiphers, ", "))
				mlkemCount++
			} else {
				fmt.Printf("    ML-KEM:   NOT SUPPORTED\n")
			}

			if portResult.TLS13Supported && portResult.MLKEMSupported {
				pqcReadyCount++
			}

			if len(portResult.TlsVersions) > 0 {
				fmt.Printf("    TLS Versions: %s\n", strings.Join(portResult.TlsVersions, ", "))
			}

			if len(portResult.AllKEMs) > 0 {
				fmt.Printf("    All KEMs: %s\n", strings.Join(portResult.AllKEMs, ", "))
			}
		}
	}

	fmt.Printf("\n========================================\n")
	fmt.Printf("SUMMARY\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Total Ports Scanned: %d\n", results.ScannedIPs)
	fmt.Printf("TLS 1.3 Ready:       %d\n", tls13Count)
	fmt.Printf("ML-KEM Ready:        %d\n", mlkemCount)
	fmt.Printf("Fully PQC Ready:     %d (TLS 1.3 + ML-KEM)\n", pqcReadyCount)
	fmt.Printf("========================================\n")
}
