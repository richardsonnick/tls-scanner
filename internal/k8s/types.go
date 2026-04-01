package k8s

import (
	"sync"

	configclientset "github.com/openshift/client-go/config/clientset/versioned"
	mcfgclientset "github.com/openshift/client-go/machineconfiguration/clientset/versioned"
	operatorclientset "github.com/openshift/client-go/operator/clientset/versioned"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type PodInfo struct {
	Name       string
	Namespace  string
	Image      string
	IPs        []string
	Containers []string
	Pod        *v1.Pod `json:"-"`
}

type ListenInfo struct {
	Port          int
	ListenAddress string
	ProcessName   string
}

type OpenshiftComponent struct {
	Component           string `json:"component"`
	SourceLocation      string `json:"source_location"`
	MaintainerComponent string `json:"maintainer_component"`
	IsBundle            bool   `json:"is_bundle"`
}

type TLSSecurityProfile struct {
	IngressController *IngressTLSProfile   `json:"ingress_controller,omitempty"`
	APIServer         *APIServerTLSProfile `json:"api_server,omitempty"`
	KubeletConfig     *KubeletTLSProfile   `json:"kubelet_config,omitempty"`
}

type IngressTLSProfile struct {
	Type          string   `json:"type,omitempty"`
	MinTLSVersion string   `json:"min_tls_version,omitempty"`
	Ciphers       []string `json:"ciphers,omitempty"`
	Raw           string   `json:"raw,omitempty"`
}

type APIServerTLSProfile struct {
	Type          string   `json:"type,omitempty"`
	MinTLSVersion string   `json:"min_tls_version,omitempty"`
	Ciphers       []string `json:"ciphers,omitempty"`
	Raw           string   `json:"raw,omitempty"`
}

type KubeletTLSProfile struct {
	TLSCipherSuites []string `json:"tls_cipher_suites,omitempty"`
	MinTLSVersion   string   `json:"tls_min_version,omitempty"`
	Raw             string   `json:"raw,omitempty"`
}

type Client struct {
	clientset                 *kubernetes.Clientset
	restCfg                   *rest.Config
	dynamicClient             dynamic.Interface
	processNameMap            map[string]map[int]string
	listenInfoMap             map[string]map[int]ListenInfo
	// procListenAddrMap holds the decoded listen address for every port seen in
	// /proc/net/tcp(6). It covers all containers in a pod (shared network
	// namespace) and is used by IsLocalhostOnly as a fallback when lsof data is
	// unavailable for a port (e.g. ports owned by secondary containers).
	procListenAddrMap         map[string]map[int]string
	processDiscoveryAttempted map[string]bool
	processCacheMutex         sync.Mutex
	namespace                 string
	configClient              *configclientset.Clientset
	operatorClient            *operatorclientset.Clientset
	mcfgClient                *mcfgclientset.Clientset
}
