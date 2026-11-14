package kubernetes

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// installerAPI uses JSON like the other adapters' typed reads and writes.
func installerAPI(config *rest.Config) (*kubernetes.Clientset, error) {
	c := rest.CopyConfig(config)
	c.ContentType, c.AcceptContentTypes = "application/json", "application/json"
	return kubernetes.NewForConfig(c)
}
