package k8s

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	configclientset "github.com/openshift/client-go/config/clientset/versioned"
	mcfgclientset "github.com/openshift/client-go/machineconfiguration/clientset/versioned"
	operatorclientset "github.com/openshift/client-go/operator/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func NewClient() (*Client, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("Could not load in-cluster config, falling back to kubeconfig: %v", err)
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		config, err = clientcmd.BuildConfigFromFlags("", loadingRules.GetDefaultFilename())
		if err != nil {
			return nil, fmt.Errorf("could not get kubernetes config: %v", err)
		}
		log.Println("Successfully created Kubernetes client from kubeconfig file")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	configClient, err := configclientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("could not create openshift config client: %v", err)
	}

	operatorClient, err := operatorclientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("could not create openshift operator client: %v", err)
	}

	mcfgClient, err := mcfgclientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("could not create openshift machineconfig client: %v", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("could not create dynamic client: %v", err)
	}

	namespace := "default"
	if nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		namespace = string(nsBytes)
	}

	return &Client{
		clientset:                 clientset,
		restCfg:                   config,
		dynamicClient:             dynamicClient,
		processNameMap:            make(map[string]map[int]string),
		listenInfoMap:             make(map[string]map[int]ListenInfo),
		processDiscoveryAttempted: make(map[string]bool),
		namespace:                 namespace,
		configClient:              configClient,
		operatorClient:            operatorClient,
		mcfgClient:                mcfgClient,
	}, nil
}

func (c *Client) GetAllPodsInfo() ([]PodInfo, error) {
	log.Println("Getting all pods from the cluster...")
	pods, err := c.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("could not list pods: %w", err)
	}

	var allPodsInfo []PodInfo
	for _, pod := range pods.Items {
		if pod.Status.PodIP == "" {
			log.Printf("Skipping pod %s/%s: no IP address assigned (phase: %s)", pod.Namespace, pod.Name, pod.Status.Phase)
			continue
		}

		containerNames := make([]string, 0, len(pod.Spec.Containers))
		for _, container := range pod.Spec.Containers {
			containerNames = append(containerNames, container.Name)
		}

		image := ""
		if len(pod.Spec.Containers) > 0 {
			image = pod.Spec.Containers[0].Image
		}

		podInfo := PodInfo{
			Name:       pod.Name,
			Namespace:  pod.Namespace,
			IPs:        []string{pod.Status.PodIP},
			Image:      image,
			Containers: containerNames,
			Pod:        &pod,
		}
		allPodsInfo = append(allPodsInfo, podInfo)
	}
	log.Printf("Found %d pods in the cluster (with IP addresses)", len(allPodsInfo))

	totalIPs := 0
	uniqueIPs := make(map[string]bool)
	for _, pod := range allPodsInfo {
		for _, ip := range pod.IPs {
			totalIPs++
			uniqueIPs[ip] = true
		}
	}
	log.Printf("IP discovery summary: %d total IPs across %d pods (%d unique IPs).", totalIPs, len(allPodsInfo), len(uniqueIPs))

	return allPodsInfo, nil
}

func (c *Client) FilterPodsByComponent(pods []PodInfo, componentFilter string) []PodInfo {
	if componentFilter == "" {
		return pods
	}

	log.Printf("Filtering pods by component name(s): %s", componentFilter)
	filterComponents := strings.Split(componentFilter, ",")
	filterSet := make(map[string]struct{})
	for _, comp := range filterComponents {
		filterSet[strings.TrimSpace(comp)] = struct{}{}
	}

	var filtered []PodInfo
	for _, pod := range pods {
		component, err := c.GetOpenshiftComponentFromImage(pod.Image)
		if err != nil {
			log.Printf("Warning: could not get component for image %s: %v", pod.Image, err)
			continue
		}
		if _, ok := filterSet[component.Component]; ok {
			filtered = append(filtered, pod)
		}
	}
	log.Printf("Filtered pods: %d remaining out of %d", len(filtered), len(pods))
	return filtered
}

func FilterPodsByNamespace(pods []PodInfo, namespaceFilter string) []PodInfo {
	if namespaceFilter == "" {
		return pods
	}

	log.Printf("Filtering pods by namespace(s): %s", namespaceFilter)
	filterNamespaces := strings.Split(namespaceFilter, ",")
	filterSet := make(map[string]struct{})
	for _, ns := range filterNamespaces {
		filterSet[strings.TrimSpace(ns)] = struct{}{}
	}

	var filtered []PodInfo
	for _, pod := range pods {
		if _, ok := filterSet[pod.Namespace]; ok {
			filtered = append(filtered, pod)
		}
	}
	log.Printf("Filtered pods by namespace: %d remaining out of %d", len(filtered), len(pods))
	return filtered
}
