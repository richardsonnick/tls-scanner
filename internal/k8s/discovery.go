package k8s

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

const procStateListen = "0A"

func DiscoverPortsFromPodSpec(pod *v1.Pod) ([]int, error) {
	log.Printf("Discovering ports for pod %s/%s from API server...", pod.Namespace, pod.Name)

	var ports []int
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.Protocol == v1.ProtocolTCP {
				ports = append(ports, int(port.ContainerPort))
			}
		}
	}

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

func (c *Client) DiscoverPortsFromProc(pod PodInfo) ([]int, error) {
	if len(pod.Containers) == 0 {
		return nil, fmt.Errorf("pod %s/%s has no containers", pod.Namespace, pod.Name)
	}

	// /proc/net/tcp is part of the network namespace, which is shared across
	// ALL containers in a pod. Reading from Containers[0] gives complete
	// visibility into every listening socket, including those owned by
	// *secondary* containers (which have separate PID namespaces and are
	// therefore invisible to lsof).
	command := []string{"/bin/sh", "-c", "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null"}
	containerName := pod.Containers[0]

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
		return nil, fmt.Errorf("failed to create executor for pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("/proc/net/tcp exec TIMED OUT in pod %s/%s (30s)", pod.Namespace, pod.Name)
		}
		return nil, fmt.Errorf("exec cat /proc/net/tcp in pod %s/%s failed: %w", pod.Namespace, pod.Name, err)
	}

	addrMap := ParseProcNetTCPWithAddrs(stdout.String())

	// Cache the decoded listen addresses so IsLocalhostOnly can use them as a
	// fallback for ports owned by secondary containers (invisible to lsof).
	if len(addrMap) > 0 {
		c.processCacheMutex.Lock()
		for _, ip := range pod.IPs {
			if _, ok := c.procListenAddrMap[ip]; !ok {
				c.procListenAddrMap[ip] = make(map[int]string)
			}
			for port, addr := range addrMap {
				if _, exists := c.procListenAddrMap[ip][port]; !exists {
					c.procListenAddrMap[ip][port] = addr
				}
			}
		}
		c.processCacheMutex.Unlock()
	}

	ports := make([]int, 0, len(addrMap))
	for port := range addrMap {
		ports = append(ports, port)
	}
	log.Printf("Discovered %d listening ports from /proc/net/tcp in pod %s/%s: %v", len(ports), pod.Namespace, pod.Name, ports)
	return ports, nil
}

// ParseProcNetTCPWithAddrs parses /proc/net/tcp (and /proc/net/tcp6) output and
// returns a map of port → decoded listen address for every socket in the LISTEN
// state. When the same port appears multiple times the first entry wins.
//
// Addresses are returned as standard Go strings: "127.0.0.1", "0.0.0.0", "::1", "::", etc.
func ParseProcNetTCPWithAddrs(output string) map[int]string {
	result := make(map[int]string)

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[3] != procStateListen {
			continue
		}

		parts := strings.SplitN(fields[1], ":", 2)
		if len(parts) != 2 {
			continue
		}

		port64, err := strconv.ParseInt(parts[1], 16, 32)
		if err != nil {
			continue
		}
		port := int(port64)

		if _, exists := result[port]; !exists {
			result[port] = decodeProcNetAddr(parts[0])
		}
	}

	return result
}

// ParseProcNetTCP returns the list of listening port numbers.
// It is a thin wrapper around ParseProcNetTCPWithAddrs that discards addresses.
func ParseProcNetTCP(output string) []int {
	addrMap := ParseProcNetTCPWithAddrs(output)
	if len(addrMap) == 0 {
		return nil
	}
	ports := make([]int, 0, len(addrMap))
	for port := range addrMap {
		ports = append(ports, port)
	}
	return ports
}

// decodeProcNetAddr converts a hex local-address field from /proc/net/tcp or
// /proc/net/tcp6 into a human-readable IP string.
//
// IPv4 entries are 8 hex characters representing a little-endian uint32.
// IPv6 entries are 32 hex characters representing four consecutive little-endian uint32s.
func decodeProcNetAddr(hexAddr string) string {
	b, err := hex.DecodeString(hexAddr)
	if err != nil {
		return hexAddr
	}

	switch len(b) {
	case 4: // IPv4 — little-endian uint32
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	case 16: // IPv6 — four consecutive little-endian uint32s
		decoded := make([]byte, 16)
		for i := 0; i < 4; i++ {
			decoded[i*4+0] = b[i*4+3]
			decoded[i*4+1] = b[i*4+2]
			decoded[i*4+2] = b[i*4+1]
			decoded[i*4+3] = b[i*4+0]
		}
		return net.IP(decoded).String()
	default:
		return hexAddr
	}
}


func UnionPorts(a, b []int) []int {
	seen := make(map[int]struct{}, len(a)+len(b))
	var result []int
	for _, p := range a {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			result = append(result, p)
		}
	}
	for _, p := range b {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			result = append(result, p)
		}
	}
	return result
}
