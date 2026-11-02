package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/targets"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Kubernetes packet peer resolution (ADR-283 PR 2). The region reads only the
// target's namespace: GETs of the named Deployment, StatefulSet, Service,
// Pod and the ReplicaSets owning listed Pods, plus paged consistent LISTs of
// Pods by label selector and of one Service's EndpointSlices. The connector
// already holds get/list on pods and get on deployments, statefulsets and
// replicasets for target resolution; Service get and EndpointSlice list are
// added for this read (regionalExecutorRBAC). No object leaves the region:
// only the resolved (UID, IP) members are answered.

const (
	peerPodPage   = 256
	peerSlicePage = 64
	// peerOwnerSets bounds the distinct ReplicaSets one resolution reads; a
	// rollout normally has one or two per Deployment.
	peerOwnerSets = 16
)

type peerPodItem struct {
	Metadata struct {
		Name, Namespace, UID string
		Labels               map[string]string
		OwnerReferences      []struct {
			APIVersion, Kind, Name, UID string
			Controller                  *bool
		}
	}
	Spec struct {
		HostNetwork bool
	}
	Status struct {
		Phase  string
		PodIP  string
		PodIPs []struct{ IP string }
	}
}

// peerReader collects one request's snapshot.
type peerReader struct {
	c         *PodTargets
	namespace string
	snapshot  value.PeerSnapshot
	pods      map[string]bool
	sets      map[string]bool
	owners    map[string]bool
	services  map[string]bool
	workloads map[string]bool
	slices    int
}

// ResolvePacketPeers lists the objects one action's Kubernetes peer entries
// name in the target's namespace and resolves them (value.ResolvePeers). A
// missing or deleting named peer is ErrPeerMissing; more Pods, slices or
// owners than the bounds is ErrPeerLimit, never a truncated set.
func (c *PodTargets) ResolvePacketPeers(ctx context.Context, r value.PeerRequest) (value.PeerResolution, error) {
	var zero value.PeerResolution
	if !r.Valid() || r.ClusterID != c.client.clusterID {
		return zero, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.client.now()
	ns, err := c.namedNamespace(ctx, r.Namespace.Name)
	if err != nil {
		return zero, err
	}
	if ns != r.Namespace {
		return zero, value.ErrChanged
	}
	p := &peerReader{c: c, namespace: ns.Name, snapshot: value.PeerSnapshot{Namespace: ns.Name}, pods: map[string]bool{}, sets: map[string]bool{}, owners: map[string]bool{}, services: map[string]bool{}, workloads: map[string]bool{}}
	for _, e := range r.Entries {
		if err := p.read(ctx, e); err != nil {
			return zero, err
		}
	}
	members, err := value.ResolvePeers(r, p.snapshot)
	if err != nil {
		return zero, err
	}
	if c.client.current(ctx, start, 5*time.Second) != nil {
		return zero, value.ErrUnavailable
	}
	out := value.PeerResolution{Request: r, Members: members}
	return out.Clone(), nil
}

// peerReadError keeps a missing object distinct from operational failures; a
// denied read is the connector's own missing permission, not the caller's.
func peerReadError(err error) error {
	switch {
	case errors.Is(err, value.ErrChanged), errors.Is(err, cfg.ErrChanged):
		return value.ErrPeerMissing
	case errors.Is(err, value.ErrLimit), errors.Is(err, value.ErrPeerLimit):
		return value.ErrPeerLimit
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	}
	return value.ErrUnavailable
}

func (p *peerReader) read(ctx context.Context, e value.PeerEntry) error {
	if e.Pods != nil {
		return p.listPods(ctx, labels.SelectorFromSet(e.Pods.MatchLabels))
	}
	ref := *e.Resource
	switch ref.Kind {
	case "Pod":
		raw, err := p.c.client.raw(ctx, "/api/v1/namespaces/"+p.namespace+"/pods/"+ref.Name, nil)
		if err != nil {
			return peerReadError(err)
		}
		var item struct {
			APIVersion, Kind string
			peerPodItem
		}
		if json.Unmarshal(raw, &item) != nil || item.APIVersion != "v1" || item.Kind != "Pod" || item.Metadata.Name != ref.Name {
			return value.ErrUnavailable
		}
		return p.addPod(item.peerPodItem)
	case "Deployment", "StatefulSet":
		w, selector, err := p.c.namedWorkload(ctx, value.WorkloadRequest{ClusterID: p.c.client.clusterID, Namespace: p.namespace, Kind: ref.Kind, Name: ref.Name})
		if err != nil {
			return peerReadError(err)
		}
		if !p.workloads[w.UID] {
			p.workloads[w.UID] = true
			p.snapshot.Workloads = append(p.snapshot.Workloads, value.PeerWorkload{Kind: w.Kind, Name: w.Name, UID: w.UID})
		}
		if err := p.listPods(ctx, selector); err != nil {
			return err
		}
		if ref.Kind == "Deployment" {
			return p.readOwners(ctx)
		}
		return nil
	}
	return p.readService(ctx, ref)
}

func (p *peerReader) listPods(ctx context.Context, selector labels.Selector) error {
	continuation, version := "", ""
	seen := map[string]bool{}
	for page := 0; page <= value.MaxPeerSnapshotPods/peerPodPage; page++ {
		raw, err := p.c.client.raw(ctx, "/api/v1/namespaces/"+p.namespace+"/pods", map[string]string{"labelSelector": selector.String(), "limit": strconv.Itoa(peerPodPage), "continue": continuation})
		if err != nil {
			return peerReadError(err)
		}
		var list struct {
			APIVersion, Kind string
			Metadata         struct{ ResourceVersion, Continue string }
			Items            []peerPodItem
		}
		if json.Unmarshal(raw, &list) != nil || list.APIVersion != "v1" || list.Kind != "PodList" || !identity.Text(list.Metadata.ResourceVersion, 128) || len(list.Items) > peerPodPage || len(list.Metadata.Continue) > 4096 || version != "" && version != list.Metadata.ResourceVersion {
			return value.ErrUnavailable
		}
		version = list.Metadata.ResourceVersion
		for _, item := range list.Items {
			if !selector.Matches(labels.Set(item.Metadata.Labels)) {
				return value.ErrUnavailable
			}
			if err := p.addPod(item); err != nil {
				return err
			}
		}
		if list.Metadata.Continue == "" {
			return nil
		}
		if seen[list.Metadata.Continue] {
			return value.ErrUnavailable
		}
		seen[list.Metadata.Continue] = true
		continuation = list.Metadata.Continue
	}
	return value.ErrPeerLimit
}

func (p *peerReader) addPod(item peerPodItem) error {
	m := item.Metadata
	if len(validation.IsDNS1123Subdomain(m.Name)) != 0 || !identity.Text(m.UID, 64) || m.Namespace != p.namespace || len(item.Status.PodIPs) > 2 {
		return value.ErrUnavailable
	}
	if p.pods[m.UID] {
		return nil
	}
	if len(p.pods) >= value.MaxPeerSnapshotPods {
		return value.ErrPeerLimit
	}
	p.pods[m.UID] = true
	pod := value.PeerPod{Name: m.Name, UID: m.UID, Labels: m.Labels, Phase: item.Status.Phase, HostNetwork: item.Spec.HostNetwork}
	for _, ip := range item.Status.PodIPs {
		pod.IPs = append(pod.IPs, ip.IP)
	}
	if len(pod.IPs) == 0 && item.Status.PodIP != "" {
		pod.IPs = []string{item.Status.PodIP}
	}
	controllers := 0
	for _, o := range m.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			controllers++
			if o.APIVersion == "apps/v1" && identity.Text(o.UID, 64) && len(validation.IsDNS1123Subdomain(o.Name)) == 0 {
				pod.ControllerKind, pod.ControllerUID = o.Kind, o.UID
				if o.Kind == "ReplicaSet" && !p.sets[o.UID] {
					// Read once in readOwners; remember the name by UID.
					p.snapshot.ReplicaSets = append(p.snapshot.ReplicaSets, value.PeerOwned{Name: o.Name, UID: o.UID})
					p.sets[o.UID] = true
				}
			}
		}
	}
	if controllers > 1 {
		return value.ErrUnavailable
	}
	p.snapshot.Pods = append(p.snapshot.Pods, pod)
	return nil
}

// readOwners GETs each referenced ReplicaSet not read yet and records its
// controller; the resolver then keeps only those a Deployment controls.
func (p *peerReader) readOwners(ctx context.Context) error {
	read := 0
	for i := range p.snapshot.ReplicaSets {
		rs := &p.snapshot.ReplicaSets[i]
		if p.owners[rs.UID] {
			continue
		}
		p.owners[rs.UID] = true
		if read++; read > peerOwnerSets {
			return value.ErrPeerLimit
		}
		o, err := p.c.object(ctx, "/apis/apps/v1/namespaces/"+p.namespace+"/replicasets/"+rs.Name, "ReplicaSet", p.namespace, rs.Name, rs.UID)
		if err != nil {
			if errors.Is(err, value.ErrChanged) {
				// A replaced or deleting ReplicaSet owns no peer.
				continue
			}
			return peerReadError(err)
		}
		if o.owner != nil && o.owner.APIVersion == "apps/v1" {
			rs.ControllerKind, rs.ControllerUID = o.owner.Kind, string(o.owner.UID)
		}
	}
	return nil
}

func (p *peerReader) readService(ctx context.Context, ref value.PeerResourceRef) error {
	raw, err := p.c.client.raw(ctx, "/api/v1/namespaces/"+p.namespace+"/services/"+ref.Name, nil)
	if err != nil {
		return peerReadError(err)
	}
	var svc struct {
		APIVersion, Kind string
		Metadata         struct {
			Name, Namespace, UID string
			DeletionTimestamp    *string
		}
		Spec struct {
			Type       string
			Selector   map[string]string
			ClusterIP  string
			ClusterIPs []string
		}
	}
	if json.Unmarshal(raw, &svc) != nil || svc.APIVersion != "v1" || svc.Kind != "Service" || svc.Metadata.Name != ref.Name || svc.Metadata.Namespace != p.namespace || !identity.Text(svc.Metadata.UID, 64) || len(svc.Spec.ClusterIPs) > 2 {
		return value.ErrUnavailable
	}
	if svc.Metadata.DeletionTimestamp != nil {
		return value.ErrPeerMissing
	}
	ips := svc.Spec.ClusterIPs
	if len(ips) == 0 && svc.Spec.ClusterIP != "" {
		ips = []string{svc.Spec.ClusterIP}
	}
	if !p.services[svc.Metadata.UID] {
		p.services[svc.Metadata.UID] = true
		p.snapshot.Services = append(p.snapshot.Services, value.PeerService{Name: svc.Metadata.Name, UID: svc.Metadata.UID, Type: svc.Spec.Type, Selector: svc.Spec.Selector, ClusterIPs: ips})
	}
	if svc.Spec.Type == "ExternalName" || len(svc.Spec.Selector) == 0 || ref.ServiceMode == "virtualIP" {
		// The resolver refuses the first two; virtual IPs need no backends.
		return nil
	}
	if err := p.listPods(ctx, labels.SelectorFromSet(svc.Spec.Selector)); err != nil {
		return err
	}
	return p.listSlices(ctx, svc.Metadata.Name)
}

func (p *peerReader) listSlices(ctx context.Context, service string) error {
	continuation, version := "", ""
	seen := map[string]bool{}
	for page := 0; page < value.MaxPeerSnapshotSlices; page++ {
		raw, err := p.c.client.raw(ctx, "/apis/discovery.k8s.io/v1/namespaces/"+p.namespace+"/endpointslices", map[string]string{"labelSelector": labels.Set{discovery.LabelServiceName: service}.AsSelector().String(), "limit": strconv.Itoa(peerSlicePage), "continue": continuation})
		if err != nil {
			return peerReadError(err)
		}
		var list discovery.EndpointSliceList
		if json.Unmarshal(raw, &list) != nil || list.APIVersion != "discovery.k8s.io/v1" || list.Kind != "EndpointSliceList" || !identity.Text(list.ResourceVersion, 128) || len(list.Items) > peerSlicePage || len(list.Continue) > 4096 || version != "" && version != list.ResourceVersion {
			return value.ErrUnavailable
		}
		version = list.ResourceVersion
		for _, item := range list.Items {
			if p.slices++; p.slices > value.MaxPeerSnapshotSlices {
				return value.ErrPeerLimit
			}
			if item.Namespace != p.namespace || item.Labels[discovery.LabelServiceName] != service || len(item.Endpoints) > 1000 {
				return value.ErrUnavailable
			}
			if item.DeletionTimestamp != nil {
				continue
			}
			slice := value.PeerEndpointSlice{ServiceName: service, Managed: item.Labels[discovery.LabelManagedBy] == "endpointslice-controller.k8s.io", AddressType: string(item.AddressType)}
			if owner, ok := ownerController(item.OwnerReferences, "Service", "v1"); ok && owner.Name == service {
				slice.ServiceUID = string(owner.UID)
			}
			for _, ep := range item.Endpoints {
				e := value.PeerEndpoint{Addresses: ep.Addresses, Ready: ep.Conditions.Ready}
				if ref := ep.TargetRef; ref != nil && ref.Kind == "Pod" && (ref.APIVersion == "" || ref.APIVersion == "v1") && ref.Namespace == p.namespace {
					e.PodUID = string(ref.UID)
				}
				slice.Endpoints = append(slice.Endpoints, e)
			}
			p.snapshot.EndpointSlices = append(p.snapshot.EndpointSlices, slice)
		}
		if list.Continue == "" {
			return nil
		}
		if seen[list.Continue] {
			return value.ErrUnavailable
		}
		seen[list.Continue] = true
		continuation = list.Continue
	}
	return value.ErrPeerLimit
}
