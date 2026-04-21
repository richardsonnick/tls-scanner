package k8s

import (
	"context"
	"fmt"
	"log"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	defaultProfileName    = "Default"
	defaultProfileType    = configv1.TLSProfileIntermediateType
	defaultProfileCiphers = configv1.TLSProfiles[defaultProfileType].Ciphers
	defaultProfileMinVer  = string(configv1.TLSProfiles[defaultProfileType].MinTLSVersion)
)

func (c *Client) GetTLSSecurityProfile() (*TLSSecurityProfile, error) {
	log.Printf("Collecting TLS security profiles from OpenShift components...")

	profile := &TLSSecurityProfile{}

	// APIServer is fetched first — it is the cluster-wide default that Ingress and
	// Kubelet inherit when no component-specific override is configured.
	if apiServerTLS, err := c.getAPIServerTLS(); err != nil {
		log.Printf("Warning: Could not get API Server TLS config: %v", err)
	} else {
		profile.APIServer = apiServerTLS
	}

	if ingressTLS, err := c.getIngressControllerTLS(profile.APIServer); err != nil {
		log.Printf("Warning: Could not get Ingress Controller TLS config: %v", err)
	} else {
		profile.IngressController = ingressTLS
	}

	if kubeletTLS, err := c.getKubeletTLS(profile.APIServer); err != nil {
		log.Printf("Warning: Could not get Kubelet TLS config: %v", err)
	} else {
		profile.KubeletConfig = kubeletTLS
	}

	return profile, nil
}

func (c *Client) getIngressControllerTLS(fallback *APIServerTLSProfile) (*IngressTLSProfile, error) {
	ingress, err := c.operatorClient.OperatorV1().IngressControllers("openshift-ingress-operator").Get(context.Background(), "default", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get IngressController custom resource: %v", err)
	}

	profile := &IngressTLSProfile{}

	if ingress.Spec.TLSSecurityProfile == nil {
		// No explicit override: inherit the cluster-wide APIServer profile.
		if fallback != nil {
			profile.Type = fallback.Type
			profile.Ciphers = fallback.Ciphers
			profile.MinTLSVersion = fallback.MinTLSVersion
		} else {
			profile.Type = defaultProfileName
			profile.Ciphers = defaultProfileCiphers
			profile.MinTLSVersion = defaultProfileMinVer
		}
		return profile, nil
	}

	profile.Type = string(ingress.Spec.TLSSecurityProfile.Type)
	if custom := ingress.Spec.TLSSecurityProfile.Custom; custom != nil {
		profile.Ciphers = custom.TLSProfileSpec.Ciphers
		profile.MinTLSVersion = string(custom.TLSProfileSpec.MinTLSVersion)
		return profile, nil
	}
	if ingress.Spec.TLSSecurityProfile.Type == configv1.TLSProfileOldType {
		profile.Ciphers = configv1.TLSProfiles[configv1.TLSProfileOldType].Ciphers
		profile.MinTLSVersion = string(configv1.TLSProfiles[configv1.TLSProfileOldType].MinTLSVersion)
	}
	if ingress.Spec.TLSSecurityProfile.Type == configv1.TLSProfileIntermediateType {
		profile.Ciphers = configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers
		profile.MinTLSVersion = string(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion)
	}
	if ingress.Spec.TLSSecurityProfile.Type == configv1.TLSProfileModernType {
		profile.Ciphers = configv1.TLSProfiles[configv1.TLSProfileModernType].Ciphers
		profile.MinTLSVersion = string(configv1.TLSProfiles[configv1.TLSProfileModernType].MinTLSVersion)
	}

	return profile, nil
}

func (c *Client) getAPIServerTLS() (*APIServerTLSProfile, error) {
	apiserver, err := c.configClient.ConfigV1().APIServers().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get APIServer custom resource: %v", err)
	}

	profile := &APIServerTLSProfile{}

	if apiserver.Spec.TLSSecurityProfile == nil {
		profile.Type = defaultProfileName
		profile.Ciphers = defaultProfileCiphers
		profile.MinTLSVersion = defaultProfileMinVer
		return profile, nil
	}

	profile.Type = string(apiserver.Spec.TLSSecurityProfile.Type)
	if custom := apiserver.Spec.TLSSecurityProfile.Custom; custom != nil {
		profile.Ciphers = custom.TLSProfileSpec.Ciphers
		profile.MinTLSVersion = string(custom.TLSProfileSpec.MinTLSVersion)
	}
	if apiserver.Spec.TLSSecurityProfile.Type == configv1.TLSProfileOldType {
		profile.Ciphers = configv1.TLSProfiles[configv1.TLSProfileOldType].Ciphers
		profile.MinTLSVersion = string(configv1.TLSProfiles[configv1.TLSProfileOldType].MinTLSVersion)
	}
	if apiserver.Spec.TLSSecurityProfile.Type == configv1.TLSProfileIntermediateType {
		profile.Ciphers = configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers
		profile.MinTLSVersion = string(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].MinTLSVersion)
	}
	if apiserver.Spec.TLSSecurityProfile.Type == configv1.TLSProfileModernType {
		profile.Ciphers = configv1.TLSProfiles[configv1.TLSProfileModernType].Ciphers
		profile.MinTLSVersion = string(configv1.TLSProfiles[configv1.TLSProfileModernType].MinTLSVersion)
	}

	return profile, nil
}

func (c *Client) getKubeletTLS(fallback *APIServerTLSProfile) (*KubeletTLSProfile, error) {
	kubeletConfigs, err := c.mcfgClient.MachineconfigurationV1().KubeletConfigs().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list KubeletConfigs: %v", err)
	}

	for _, kc := range kubeletConfigs.Items {
		if kc.Spec.TLSSecurityProfile != nil {
			profile := &KubeletTLSProfile{}
			tlsProfile := kc.Spec.TLSSecurityProfile

			if tlsProfile.Type == configv1.TLSProfileCustomType {
				if custom := tlsProfile.Custom; custom != nil {
					profile.TLSCipherSuites = custom.TLSProfileSpec.Ciphers
					profile.MinTLSVersion = string(custom.TLSProfileSpec.MinTLSVersion)
				}
			} else if tlsProfile.Type != "" {
				if predefined, ok := configv1.TLSProfiles[tlsProfile.Type]; ok {
					profile.TLSCipherSuites = predefined.Ciphers
					profile.MinTLSVersion = string(predefined.MinTLSVersion)
				}
			}
			return profile, nil
		}
	}

	// No explicit KubeletConfig override: inherit the cluster-wide APIServer profile.
	if fallback != nil {
		return &KubeletTLSProfile{
			TLSCipherSuites: fallback.Ciphers,
			MinTLSVersion:   fallback.MinTLSVersion,
		}, nil
	}

	return nil, fmt.Errorf("no KubeletConfig with a TLSSecurityProfile found in the cluster")
}
