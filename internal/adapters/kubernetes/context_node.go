package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// PodNode returns the node of the exact pinned, running Pod (ADR-248): the
// connector queues a packet capture only on that node's collector. Same reads
// as Capture (namespace and Pod by name, UID and controller checked); a Pod
// that is not running on a node is ErrTargetChanged. A host-network Pod is
// refused: its traffic cannot be attributed to it.
func (c *ContextCollector) PodNode(ctx context.Context, pin artifact.PinnedPod) (string, error) {
	if len(validation.IsDNS1123Label(pin.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(pin.Name)) != 0 || len(pin.NamespaceUID) == 0 || len(pin.UID) == 0 || c.executionClass != artifact.ContextAPIExecution || pin.NodeName != "" {
		return "", artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ns, err := c.client.Namespaces().Get(ctx, pin.Namespace, meta.GetOptions{})
	if err != nil {
		return "", contextError(err)
	}
	if string(ns.UID) != pin.NamespaceUID {
		return "", ErrTargetChanged
	}
	p, err := c.client.Pods(pin.Namespace).Get(ctx, pin.Name, meta.GetOptions{})
	if err != nil {
		return "", contextError(err)
	}
	if string(p.UID) != pin.UID || p.Namespace != pin.Namespace || p.Name != pin.Name || p.DeletionTimestamp != nil {
		return "", ErrTargetChanged
	}
	owner := meta.GetControllerOf(p)
	if (owner == nil && pin.ControllerUID != "") || (owner != nil && (pin.ControllerUID == "" || string(owner.UID) != pin.ControllerUID)) {
		return "", ErrTargetChanged
	}
	if p.Status.Phase != core.PodRunning || p.Spec.HostNetwork || len(validation.IsDNS1123Subdomain(p.Spec.NodeName)) != 0 {
		return "", ErrTargetChanged
	}
	return p.Spec.NodeName, nil
}
