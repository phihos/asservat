package kubernetes

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"

	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
)

type ownerOperationRoute struct {
	pod, node string
	addresses []string
}

// This fixed one/two-owner boundary performs one complete LIST, retaining the
// existing page/RV/object/address bounds. It is not installation discovery and
// never infers a process binding from a Pod or a latest registration.
func (s *OwnerEndpoints) observationOperationRoutes(ctx context.Context, bindings []value.OwnerBinding) (map[string]ownerOperationRoute, error) {
	p := s.pool
	wanted := make(map[string]bool, len(bindings))
	for _, b := range bindings {
		wanted[b.PodUID] = true
	}
	found := make(map[string]ownerOperationRoute, len(wanted))
	continuation, version := "", ""
	seen := map[string]bool{}
	total, count, endpoints := 0, 0, 0
	for page := 0; page < 64; page++ {
		raw, err := s.client.raw(ctx, "/apis/discovery.k8s.io/v1/namespaces/"+p.Namespace+"/endpointslices", map[string]string{"labelSelector": labels.Set{"kubernetes.io/service-name": p.Service}.AsSelector().String(), "limit": "64", "continue": continuation})
		total += len(raw)
		var list discovery.EndpointSliceList
		if err != nil || total > 8<<20 || json.Unmarshal(raw, &list) != nil || list.APIVersion != "discovery.k8s.io/v1" || list.Kind != "EndpointSliceList" || !identity.Text(list.ResourceVersion, 128) || len(list.Items) > 64 || count+len(list.Items) > 64 || len(list.Continue) > 4096 || version != "" && version != list.ResourceVersion {
			return nil, value.ErrUnavailable
		}
		version, count = list.ResourceVersion, count+len(list.Items)
		for _, item := range list.Items {
			endpoints += len(item.Endpoints)
			owner, ok := ownerController(item.OwnerReferences, "Service", "v1")
			if !ok || owner.Name != p.Service || string(owner.UID) != p.ServiceUID || item.Namespace != p.Namespace || item.DeletionTimestamp != nil || item.Labels["kubernetes.io/service-name"] != p.Service || item.Labels["endpointslice.kubernetes.io/managed-by"] != "endpointslice-controller.k8s.io" || endpoints > 1024 || !ownerSlicePorts(p, item.Ports) || (item.AddressType != discovery.AddressTypeIPv4 && item.AddressType != discovery.AddressTypeIPv6) {
				return nil, value.ErrUnavailable
			}
			for _, ep := range item.Endpoints {
				ref := ep.TargetRef
				if ref == nil || !wanted[string(ref.UID)] {
					continue
				}
				route := found[string(ref.UID)]
				if (ref.APIVersion != "" && ref.APIVersion != "v1") || ref.Kind != "Pod" || ref.Namespace != p.Namespace || ref.Name == "" || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 || ep.NodeName == nil || !identity.Text(*ep.NodeName, 253) || ep.Conditions.Ready == nil || !*ep.Conditions.Ready || ep.Conditions.Serving != nil && !*ep.Conditions.Serving || ep.Conditions.Terminating != nil && *ep.Conditions.Terminating || len(ep.Addresses) < 1 || len(ep.Addresses) > 2 || route.pod != "" && (route.pod != ref.Name || route.node != *ep.NodeName) {
					return nil, value.ErrUnavailable
				}
				route.pod, route.node = ref.Name, *ep.NodeName
				for _, ip := range ep.Addresses {
					addr, e := netip.ParseAddr(ip)
					if e != nil || !value.OwnerAddress(ip) || addr.Is4() != (item.AddressType == discovery.AddressTypeIPv4) {
						return nil, value.ErrUnavailable
					}
					if !slices.Contains(route.addresses, ip) {
						route.addresses = append(route.addresses, ip)
					}
					if len(route.addresses) > 2 {
						return nil, value.ErrUnavailable
					}
				}
				found[string(ref.UID)] = route
			}
		}
		if list.Continue == "" {
			for uid := range wanted {
				r := found[uid]
				if r.pod == "" || len(r.addresses) == 0 {
					return nil, value.ErrUnavailable
				}
				slices.Sort(r.addresses)
				found[uid] = r
			}
			return found, nil
		}
		if seen[list.Continue] {
			return nil, value.ErrUnavailable
		}
		seen[list.Continue] = true
		continuation = list.Continue
	}
	return nil, value.ErrUnavailable
}
