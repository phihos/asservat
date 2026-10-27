package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/targets"
	"k8s.io/apimachinery/pkg/util/validation"
)

// resolveAPIContextPod retains object/owner identity and its original interval.
// Assignment is observation data, not an execution location or authorization
// condition. A Pod becoming scheduled cannot change this API-only target pin.
func (c *PodTargets) resolveAPIContextPod(ctx context.Context, r value.Request) (value.PodResolution, error) {
	p, _, err := c.resolveAPIContextPodWithPacketNode(ctx, r)
	return p, err
}

// ResolvePacketPod reuses the same exact final Pod read for packet readiness.
// The node name stays local to the regional composition, outside the API pin.
func (c *PodTargets) ResolvePacketPod(ctx context.Context, r value.Request) (value.PodResolution, string, error) {
	if c.executionClass != artifact.ContextAPIExecution || !r.Valid() || r.ClusterID != c.client.clusterID || len(validation.IsDNS1123Label(r.Namespace.Name)) != 0 || len(validation.IsDNS1123Subdomain(r.PodName)) != 0 || len(validation.IsDNS1123Subdomain(r.Workload.Name)) != 0 {
		return value.PodResolution{}, "", value.ErrInvalid
	}
	return c.resolveAPIContextPodWithPacketNode(ctx, r)
}

func (c *PodTargets) resolveAPIContextPodWithPacketNode(ctx context.Context, r value.Request) (value.PodResolution, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.client.now()
	ns, err := c.client.namespace(ctx, r.Namespace)
	if err != nil {
		return value.PodResolution{}, "", targetReadError(err)
	}
	if ns.Deleting {
		return value.PodResolution{}, "", value.ErrChanged
	}
	path := "/api/v1/namespaces/" + r.Namespace.Name + "/pods/" + r.PodName
	first, err := c.object(ctx, path, "Pod", r.Namespace.Name, r.PodName, r.PodUID)
	if err != nil {
		return value.PodResolution{}, "", err
	}
	if _, err = c.chain(ctx, r, first); err != nil {
		return value.PodResolution{}, "", err
	}
	last, err := c.object(ctx, path, "Pod", r.Namespace.Name, r.PodName, r.PodUID)
	if err != nil {
		return value.PodResolution{}, "", err
	}
	if (last.owner == nil) != (first.owner == nil) || (last.owner != nil && !ownerMatches(last.owner, first.owner.Kind, first.owner.Name, string(first.owner.UID))) {
		return value.PodResolution{}, "", value.ErrChanged
	}
	rv, err := c.chain(ctx, r, last)
	if err != nil {
		return value.PodResolution{}, "", err
	}
	ns, err = c.client.namespace(ctx, r.Namespace)
	if err != nil {
		return value.PodResolution{}, "", targetReadError(err)
	}
	if ns.Deleting {
		return value.PodResolution{}, "", value.ErrChanged
	}
	out := value.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: r, Pin: artifact.PinnedPod{Namespace: r.Namespace.Name, NamespaceUID: r.Namespace.UID, Name: r.PodName, UID: r.PodUID}, PodResourceVersion: last.ref.ResourceVersion, WorkloadResourceVersion: rv, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}
	if last.owner != nil {
		out.Pin.ControllerUID = string(last.owner.UID)
	}
	// The completed API snapshot keeps its own first-read observation window.
	// The original context still bounds every read and the current check below;
	// a shorter transport/owner lease is not the lifetime of this metadata.
	if c.client.current(ctx, start, 5*time.Second) != nil || !out.Valid(c.client.now()) {
		return value.PodResolution{}, "", value.ErrUnavailable
	}
	node := ""
	if last.packetEligible {
		node = last.node
	}
	return out, node, nil
}
