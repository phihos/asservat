package bootstrap

import (
	"asservat.local/asservat/internal/adapters/mounts"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// localKubernetes follows kubectl's KUBECONFIG/current-context conventions and
// named overrides, with no in-cluster credential fallback.
func localKubernetes(kubeconfig, selected, namespace string) (*rest.Config, string, string, error) {
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	loading.ExplicitPath = kubeconfig
	raw, err := loading.Load()
	if err != nil {
		return nil, "", "", mounts.ErrUnavailable
	}
	current := raw.CurrentContext
	if selected != "" {
		current = selected
	}
	if current == "" || len(current) > 256 || raw.Contexts[current] == nil {
		return nil, "", "", mounts.ErrUnavailable
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: current}
	if namespace != "" {
		overrides.Context.Namespace = namespace
	}
	// Direct local-config construction deliberately avoids the deferred
	// loader's fallback to a Pod's ambient in-cluster credentials.
	client := clientcmd.NewNonInteractiveClientConfig(*raw, current, overrides, loading)
	configuration, err := client.ClientConfig()
	if err != nil {
		return nil, "", "", mounts.ErrUnavailable
	}
	resolved, _, err := client.Namespace()
	if err != nil {
		return nil, "", "", mounts.ErrUnavailable
	}
	return configuration, current, resolved, nil
}

// RunInstallerProviderApply is the ADR-183 operator command. It uses the
// operator's own OpenBao administration (BAO_ADDR, BAO_CACERT, BAO_TOKEN) and
