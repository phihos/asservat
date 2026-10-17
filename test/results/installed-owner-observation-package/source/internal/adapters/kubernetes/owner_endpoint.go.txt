package kubernetes

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
)

type OwnerEndpoints struct {
	client *PermissionClient
	pool   value.OwnerPool
}

var _ app.OwnerEndpointReader = (*OwnerEndpoints)(nil)

func NewOwnerEndpoints(c *PermissionClient, p value.OwnerPool) (*OwnerEndpoints, error) {
	if c == nil || !p.Valid() || c.clusterID != p.ClusterID || c.control.Name != p.Namespace || c.control.UID != p.NamespaceUID || len(validation.IsDNS1123Label(p.Namespace)) != 0 || len(validation.IsDNS1035Label(p.Service)) != 0 || len(validation.IsDNS1123Subdomain(p.Deployment)) != 0 || len(validation.IsDNS1123Subdomain(p.ServiceAccount)) != 0 {
		return nil, value.ErrInvalid
	}
	return &OwnerEndpoints{c, p}, nil
}

func ownerMetadata(m meta.ObjectMeta, namespace, name, uid string) bool {
	return m.Name == name && m.Namespace == namespace && string(m.UID) == uid && m.DeletionTimestamp == nil && identity.Text(m.ResourceVersion, 128)
}
func ownerController(refs []meta.OwnerReference, kind, version string) (meta.OwnerReference, bool) {
	var found meta.OwnerReference
	count := 0
	if len(refs) > 8 {
		return found, false
	}
	for _, r := range refs {
		if r.Controller != nil && *r.Controller {
			count++
			found = r
		}
	}
	return found, count == 1 && found.Kind == kind && found.APIVersion == version && len(validation.IsDNS1123Subdomain(found.Name)) == 0 && found.Name != "" && identity.Text(string(found.UID), 64)
}
func ownerResource[T any](s *OwnerEndpoints, ctx context.Context, path, version, kind string) (T, error) {
	var out T
	b, err := s.client.raw(ctx, path, nil)
	if err != nil {
		return out, err
	}
	o, err := objectEnvelope(b)
	if err != nil || o.APIVersion != version || o.Kind != kind || json.Unmarshal(b, &out) != nil {
		return out, value.ErrUnavailable
	}
	return out, nil
}

func (s *OwnerEndpoints) service(ctx context.Context) (core.Service, error) {
	p := s.pool
	v, err := ownerResource[core.Service](s, ctx, "/api/v1/namespaces/"+p.Namespace+"/services/"+p.Service, "v1", "Service")
	if err != nil || !ownerMetadata(v.ObjectMeta, p.Namespace, p.Service, p.ServiceUID) || v.Spec.Type != core.ServiceTypeClusterIP || v.Spec.PublishNotReadyAddresses || len(v.Spec.Selector) < 1 || len(v.Spec.Selector) > 32 || len(v.Spec.ExternalIPs) != 0 || v.Spec.ExternalName != "" || v.Spec.LoadBalancerIP != "" || !ownerServicePorts(p, v.Spec.Ports) {
		return v, value.ErrUnavailable
	}
	if _, err = labels.ValidatedSelectorFromSet(v.Spec.Selector); err != nil {
		return v, value.ErrInvalid
	}
	return v, nil
}

func (s *OwnerEndpoints) OwnerEndpoint(ctx context.Context, binding value.OwnerBinding) (value.OwnerEndpoint, error) {
	var out value.OwnerEndpoint
	if s == nil || ctx == nil || !binding.Valid() || binding.InstallationID != s.pool.InstallationID || binding.ClusterID != s.pool.ClusterID || binding.IssuerEpoch != s.pool.IssuerEpoch {
		return out, value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start, p := s.client.now(), s.pool
	if _, err := s.client.namespace(ctx, s.client.control); err != nil {
		return out, err
	}
	service, err := s.service(ctx)
	if err != nil {
		return out, err
	}
	account, err := ownerResource[core.ServiceAccount](s, ctx, "/api/v1/namespaces/"+p.Namespace+"/serviceaccounts/"+p.ServiceAccount, "v1", "ServiceAccount")
	if err != nil || !ownerMetadata(account.ObjectMeta, p.Namespace, p.ServiceAccount, p.AccountUID) {
		return out, value.ErrUnavailable
	}
	deployment, err := ownerResource[apps.Deployment](s, ctx, "/apis/apps/v1/namespaces/"+p.Namespace+"/deployments/"+p.Deployment, "apps/v1", "Deployment")
	if err != nil || !ownerMetadata(deployment.ObjectMeta, p.Namespace, p.Deployment, p.DeploymentUID) || deployment.Spec.Selector == nil {
		return out, value.ErrUnavailable
	}
	podName, nodeName, addresses, err := s.endpoints(ctx, binding.PodUID)
	if err != nil {
		return out, err
	}
	pod, err := ownerResource[core.Pod](s, ctx, "/api/v1/namespaces/"+p.Namespace+"/pods/"+podName, "v1", "Pod")
	if err != nil || !ownerMetadata(pod.ObjectMeta, p.Namespace, podName, binding.PodUID) || pod.Spec.ServiceAccountName != p.ServiceAccount || pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC || pod.Status.Phase != core.PodRunning || pod.Spec.NodeName != nodeName || len(pod.Status.PodIPs) < 1 || len(pod.Status.PodIPs) > 2 {
		return out, value.ErrUnavailable
	}
	ready, readyConditions := false, 0
	for _, c := range pod.Status.Conditions {
		if c.Type == core.PodReady {
			readyConditions++
			ready = c.Status == core.ConditionTrue
		}
	}
	selector, err := meta.LabelSelectorAsSelector(deployment.Spec.Selector)
	if err != nil || !selector.Matches(labels.Set(pod.Labels)) || !labels.SelectorFromSet(service.Spec.Selector).Matches(labels.Set(pod.Labels)) || !ready || readyConditions != 1 {
		return out, value.ErrUnavailable
	}
	for _, address := range addresses {
		if !slices.ContainsFunc(pod.Status.PodIPs, func(ip core.PodIP) bool { return ip.IP == address }) {
			return out, value.ErrUnavailable
		}
	}
	rs, ok := ownerController(pod.OwnerReferences, "ReplicaSet", "apps/v1")
	if !ok {
		return out, value.ErrUnavailable
	}
	replica, err := ownerResource[apps.ReplicaSet](s, ctx, "/apis/apps/v1/namespaces/"+p.Namespace+"/replicasets/"+rs.Name, "apps/v1", "ReplicaSet")
	if err != nil || !ownerMetadata(replica.ObjectMeta, p.Namespace, rs.Name, string(rs.UID)) {
		return out, value.ErrUnavailable
	}
	d, ok := ownerController(replica.OwnerReferences, "Deployment", "apps/v1")
	if !ok || d.Name != p.Deployment || string(d.UID) != p.DeploymentUID {
		return out, value.ErrUnavailable
	}
	// Do not return an endpoint from a changed Service or Pod read earlier in
	// the sequence. TLS must still prove the exact process on connection.
	latest, err := s.service(ctx)
	if err != nil || latest.ResourceVersion != service.ResourceVersion {
		return out, value.ErrUnavailable
	}
	current, err := ownerResource[core.Pod](s, ctx, "/api/v1/namespaces/"+p.Namespace+"/pods/"+podName, "v1", "Pod")
	if err != nil || current.ResourceVersion != pod.ResourceVersion || !ownerMetadata(current.ObjectMeta, p.Namespace, podName, binding.PodUID) || s.client.current(ctx, start, 5*time.Second) != nil {
		return out, value.ErrUnavailable
	}
	out = value.OwnerEndpoint{Binding: binding, Pool: p, Pod: podName, ReplicaSetUID: string(rs.UID), Addresses: addresses, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}
	if !out.Valid(s.client.now()) {
		return value.OwnerEndpoint{}, value.ErrUnavailable
	}
	return out, nil
}

func (s *OwnerEndpoints) endpoints(ctx context.Context, uid string) (string, string, []string, error) {
	p := s.pool
	continuation, version, pod, node := "", "", "", ""
	seen := map[string]bool{}
	addresses := map[string]bool{}
	total, count, endpoints := 0, 0, 0
	for page := 0; page < 64; page++ {
		b, err := s.client.raw(ctx, "/apis/discovery.k8s.io/v1/namespaces/"+p.Namespace+"/endpointslices", map[string]string{"labelSelector": labels.Set{"kubernetes.io/service-name": p.Service}.AsSelector().String(), "limit": "64", "continue": continuation})
		total += len(b)
		var list discovery.EndpointSliceList
		if err != nil || total > 8<<20 || json.Unmarshal(b, &list) != nil || list.APIVersion != "discovery.k8s.io/v1" || list.Kind != "EndpointSliceList" || !identity.Text(list.ResourceVersion, 128) || len(list.Items) > 64 || count+len(list.Items) > 64 || len(list.Continue) > 4096 || version != "" && version != list.ResourceVersion {
			return "", "", nil, value.ErrUnavailable
		}
		version, count = list.ResourceVersion, count+len(list.Items)
		for _, item := range list.Items {
			endpoints += len(item.Endpoints)
			owner, ok := ownerController(item.OwnerReferences, "Service", "v1")
			if !ok || owner.Name != p.Service || string(owner.UID) != p.ServiceUID || item.Namespace != p.Namespace || item.DeletionTimestamp != nil || item.Labels["kubernetes.io/service-name"] != p.Service || item.Labels["endpointslice.kubernetes.io/managed-by"] != "endpointslice-controller.k8s.io" || endpoints > 1024 || !ownerSlicePorts(p, item.Ports) || (item.AddressType != discovery.AddressTypeIPv4 && item.AddressType != discovery.AddressTypeIPv6) {
				return "", "", nil, value.ErrUnavailable
			}
			for _, endpoint := range item.Endpoints {
				ref := endpoint.TargetRef
				if ref == nil || string(ref.UID) != uid {
					continue
				}
				// The standard EndpointSlice controller omits ObjectReference's
				// optional apiVersion. Independently GET the exact core/v1 Pod;
				// an explicitly foreign version is still not acceptable.
				if (ref.APIVersion != "" && ref.APIVersion != "v1") || ref.Kind != "Pod" || ref.Namespace != p.Namespace || ref.Name == "" || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 || endpoint.NodeName == nil || !identity.Text(*endpoint.NodeName, 253) || endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready || endpoint.Conditions.Serving != nil && !*endpoint.Conditions.Serving || endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating || len(endpoint.Addresses) < 1 || len(endpoint.Addresses) > 2 || pod != "" && (pod != ref.Name || node != *endpoint.NodeName) {
					return "", "", nil, value.ErrUnavailable
				}
				pod, node = ref.Name, *endpoint.NodeName
				for _, address := range endpoint.Addresses {
					a, err := netip.ParseAddr(address)
					if err != nil || !value.OwnerAddress(address) || a.Is4() != (item.AddressType == discovery.AddressTypeIPv4) {
						return "", "", nil, value.ErrUnavailable
					}
					addresses[address] = true
					if len(addresses) > 2 {
						return "", "", nil, value.ErrUnavailable
					}
				}
			}
		}
		if list.Continue == "" {
			out := make([]string, 0, len(addresses))
			for a := range addresses {
				out = append(out, a)
			}
			slices.Sort(out)
			if pod == "" || len(out) == 0 {
				return "", "", nil, value.ErrUnavailable
			}
			return pod, node, out, nil
		}
		if seen[list.Continue] {
			return "", "", nil, value.ErrUnavailable
		}
		seen[list.Continue] = true
		continuation = list.Continue
	}
	return "", "", nil, value.ErrUnavailable
}
