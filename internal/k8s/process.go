package k8s

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

func (c *Client) GetProcessMapForPod(pod PodInfo) (map[string]map[int]string, map[string]map[int]ListenInfo, error) {
	processMap := make(map[string]map[int]string)
	listenInfoMap := make(map[string]map[int]ListenInfo)
	if len(pod.Containers) == 0 {
		return processMap, listenInfoMap, nil
	}

	command := []string{"/bin/sh", "-c", "lsof -i -sTCP:LISTEN -P -n -F cn"}
	containerName := pod.Containers[0]
	log.Printf("Executing lsof command in pod %s/%s, container %s: %v", pod.Namespace, pod.Name, containerName, command)

	req := c.clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec")

	req.VersionedParams(&v1.PodExecOptions{
		Container: containerName,
		Command:   command,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(c.restCfg, "POST", req.URL())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create executor for pod %s: %v", pod.Name, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	log.Printf("lsof command for pod %s/%s finished.", pod.Namespace, pod.Name)
	log.Printf("lsof stdout:\n%s", stdout.String())
	log.Printf("lsof stderr:\n%s", stderr.String())

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, nil, fmt.Errorf("lsof exec TIMED OUT in pod %s/%s (30s)", pod.Namespace, pod.Name)
		}
		return nil, nil, fmt.Errorf("exec failed on pod %s: %v, stdout: %s, stderr: %s", pod.Name, err, stdout.String(), stderr.String())
	}

	if stdout.Len() == 0 {
		log.Printf("lsof command returned empty stdout for pod %s/%s.", pod.Namespace, pod.Name)
	}

	scanner := bufio.NewScanner(&stdout)
	var currentProcess string
	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("Parsing lsof output line for pod %s/%s: %q", pod.Namespace, pod.Name, line)
		if len(line) > 1 {
			fieldType := line[0]
			fieldValue := line[1:]

			switch fieldType {
			case 'c':
				currentProcess = fieldValue
			case 'n':
				parts := strings.Split(fieldValue, ":")
				if len(parts) == 2 {
					listenAddr := parts[0]
					portStr := parts[1]
					port, err := strconv.Atoi(portStr)
					if err == nil {
						for _, ip := range pod.IPs {
							if _, ok := processMap[ip]; !ok {
								processMap[ip] = make(map[int]string)
							}
							if _, ok := listenInfoMap[ip]; !ok {
								listenInfoMap[ip] = make(map[int]ListenInfo)
							}
							processMap[ip][port] = currentProcess
							listenInfoMap[ip][port] = ListenInfo{
								Port:          port,
								ListenAddress: listenAddr,
								ProcessName:   currentProcess,
							}
							log.Printf("Mapped pod %s/%s IP %s port %d to process %s (listen addr: %s)", pod.Namespace, pod.Name, ip, port, currentProcess, listenAddr)
						}
					} else {
						log.Printf("Error converting port to integer for pod %s/%s: '%s' from line '%s'", pod.Namespace, pod.Name, portStr, line)
					}
				} else {
					log.Printf("Unexpected format for network address from lsof for pod %s/%s: '%s'", pod.Namespace, pod.Name, fieldValue)
				}
			}
		}
	}

	return processMap, listenInfoMap, nil
}

func (c *Client) GetAndCachePodProcesses(pod PodInfo) map[string]map[int]string {
	c.processCacheMutex.Lock()
	if c.processDiscoveryAttempted[pod.Name] {
		c.processCacheMutex.Unlock()
		return nil
	}
	c.processDiscoveryAttempted[pod.Name] = true
	c.processCacheMutex.Unlock()

	processMap, listenInfoMap, err := c.GetProcessMapForPod(pod)
	if err != nil {
		log.Printf("Could not get process map for pod %s/%s: %v", pod.Namespace, pod.Name, err)
		return nil
	}

	if len(processMap) > 0 || len(listenInfoMap) > 0 {
		c.processCacheMutex.Lock()
		defer c.processCacheMutex.Unlock()
		for ip, portMap := range processMap {
			if _, ok := c.processNameMap[ip]; !ok {
				c.processNameMap[ip] = make(map[int]string)
			}
			for port, process := range portMap {
				c.processNameMap[ip][port] = process
			}
		}
		for ip, portMap := range listenInfoMap {
			if _, ok := c.listenInfoMap[ip]; !ok {
				c.listenInfoMap[ip] = make(map[int]ListenInfo)
			}
			for port, info := range portMap {
				c.listenInfoMap[ip][port] = info
			}
		}
	}

	return processMap
}

func (c *Client) IsLocalhostOnly(ip string, port int) (bool, string) {
	c.processCacheMutex.Lock()
	defer c.processCacheMutex.Unlock()

	// Primary source: lsof data (covers ports visible from Containers[0]).
	// When lsof has an entry for this port, treat it as authoritative and do
	// not fall through to proc data — lsof provides richer process context and
	// its bind address should be trusted over the kernel's /proc view.
	if portMap, ok := c.listenInfoMap[ip]; ok {
		if info, ok := portMap[port]; ok {
			if isLocalhostAddr(info.ListenAddress) {
				return true, info.ListenAddress
			}
			return false, ""
		}
	}

	// Fallback: /proc/net/tcp data (covers all containers via shared network
	// namespace, including ports owned by secondary containers that are
	// invisible to lsof due to PID namespace isolation).
	if addrMap, ok := c.procListenAddrMap[ip]; ok {
		if addr, ok := addrMap[port]; ok {
			if isLocalhostAddr(addr) {
				return true, addr
			}
		}
	}

	return false, ""
}

// isLocalhostAddr reports whether addr is a loopback address.
func isLocalhostAddr(addr string) bool {
	return addr == "127.0.0.1" || addr == "::1" || addr == "localhost"
}

func (c *Client) GetListenInfo(ip string, port int) (ListenInfo, bool) {
	c.processCacheMutex.Lock()
	defer c.processCacheMutex.Unlock()

	if portMap, ok := c.listenInfoMap[ip]; ok {
		if info, ok := portMap[port]; ok {
			return info, true
		}
	}
	return ListenInfo{}, false
}

func (c *Client) GetProcessName(ip string, port int) (string, bool) {
	c.processCacheMutex.Lock()
	defer c.processCacheMutex.Unlock()

	if portMap, ok := c.processNameMap[ip]; ok {
		if name, ok := portMap[port]; ok {
			return name, true
		}
	}
	return "", false
}
