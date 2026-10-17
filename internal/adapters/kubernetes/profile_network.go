package kubernetes

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	port "asservat.local/asservat/internal/application/targets"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/targets"
	"k8s.io/apimachinery/pkg/util/validation"
)

var _ port.ProfileNetworkReader = (*PodTargets)(nil)

// ObserveProfileNetwork reads passive routing facts, then reuses the existing
// exact namespace/Pod/owner/node resolution. The final Pod version must match
// the initial routing response. No replacement selection or endpoint probing
// occurs, and the original outer interval covers all constituent reads.
func (c *PodTargets) ObserveProfileNetwork(parent context.Context, r value.Request) (value.ProfileNetwork, error) {
	var out value.ProfileNetwork
	if parent == nil || c == nil || c.client == nil || c.executionClass != artifact.ContextNodeExecution || !r.Valid() || r.ClusterID != c.client.clusterID || len(validation.IsDNS1123Label(r.Namespace.Name)) != 0 || len(validation.IsDNS1123Subdomain(r.PodName)) != 0 {
		return out, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	start := c.client.now()
	if ctx.Err() != nil {
		return out, value.ErrUnavailable
	}
	raw, err := c.client.raw(ctx, "/api/v1/namespaces/"+r.Namespace.Name+"/pods/"+r.PodName, nil)
	if err != nil {
		return out, targetReadError(err)
	}
	network, observed, err := decodeProfileNetwork(raw)
	if err != nil {
		return out, err
	}
	if observed.Name != r.PodName || observed.Namespace != r.Namespace.Name || observed.UID != r.PodUID || observed.Deleting {
		return out, value.ErrChanged
	}
	resolved, err := c.ResolvePod(ctx, r)
	if err != nil {
		return out, err
	}
	if resolved.PodResourceVersion != observed.RV || resolved.Pin.NodeName != observed.Node {
		return out, value.ErrChanged
	}
	resolved.ObservedAt = start
	resolved.FreshUntil = identity.Earlier(start.Add(5*time.Second), resolved.FreshUntil)
	if deadline, ok := ctx.Deadline(); ok {
		resolved.FreshUntil = identity.Earlier(resolved.FreshUntil, deadline)
	}
	network.Target = resolved
	if c.client.current(ctx, start, 5*time.Second) != nil || !network.Valid(c.client.now()) {
		return out, value.ErrUnavailable
	}
	return network, nil
}

// Decode only routing fields. API response bounds belong to PermissionClient;
// container/environment/configuration contents never enter the returned value.
type profileNetworkMetadata struct {
	permissionMetadata
	Node string
}

func decodeProfileNetwork(raw []byte) (value.ProfileNetwork, profileNetworkMetadata, error) {
	var out value.ProfileNetwork
	var metadata profileNetworkMetadata
	var fields, m, spec map[string]json.RawMessage
	bad := func() (value.ProfileNetwork, profileNetworkMetadata, error) {
		return value.ProfileNetwork{}, profileNetworkMetadata{}, value.ErrUnavailable
	}
	if json.Unmarshal(raw, &fields) != nil || json.Unmarshal(fields["metadata"], &m) != nil || json.Unmarshal(fields["spec"], &spec) != nil || spec == nil {
		return bad()
	}
	var kind, api string
	if json.Unmarshal(fields["kind"], &kind) != nil || kind != "Pod" || json.Unmarshal(fields["apiVersion"], &api) != nil || api != "v1" {
		return bad()
	}
	for key, dst := range map[string]*string{"name": &metadata.Name, "namespace": &metadata.Namespace, "uid": &metadata.UID, "resourceVersion": &metadata.RV} {
		if json.Unmarshal(m[key], dst) != nil || !identity.Text(*dst, 253) {
			return bad()
		}
	}
	metadata.Deleting = m["deletionTimestamp"] != nil && string(m["deletionTimestamp"]) != "null"
	if b, exists := spec["hostNetwork"]; exists {
		if string(b) == "null" || json.Unmarshal(b, &out.HostNetwork) != nil {
			return bad()
		}
	}
	if json.Unmarshal(spec["nodeName"], &metadata.Node) != nil || len(validation.IsDNS1123Subdomain(metadata.Node)) != 0 {
		return bad()
	}
	containers := 0
	for _, field := range []string{"containers", "initContainers", "ephemeralContainers"} {
		b, exists := spec[field]
		if !exists && field != "containers" {
			continue
		}
		var entries []map[string]json.RawMessage
		if json.Unmarshal(b, &entries) != nil || (field == "containers" && len(entries) == 0) || len(entries)+containers > 256 {
			return bad()
		}
		containers += len(entries)
		for _, entry := range entries {
			if entry == nil {
				return bad()
			}
			var ports []map[string]json.RawMessage
			if b, exists := entry["ports"]; exists {
				if string(b) == "null" || json.Unmarshal(b, &ports) != nil || len(ports)+len(out.Ports) > value.MaxProfilePodPorts || (field == "ephemeralContainers" && len(ports) > 0) {
					return bad()
				}
			}
			for _, fields := range ports {
				p := value.ProfilePodPort{Protocol: "TCP"}
				if json.Unmarshal(fields["containerPort"], &p.Port) != nil || p.Port == 0 {
					return bad()
				}
				for key, dst := range map[string]*string{"name": &p.Name, "protocol": &p.Protocol} {
					if b, exists := fields[key]; exists && (string(b) == "null" || json.Unmarshal(b, dst) != nil) {
						return bad()
					}
				}
				if p.Name != "" && len(validation.IsValidPortName(p.Name)) != 0 {
					return bad()
				}
				out.Ports = append(out.Ports, p)
			}
		}
	}
	if b, exists := fields["status"]; exists {
		var status map[string]json.RawMessage
		if json.Unmarshal(b, &status) != nil || status == nil {
			return bad()
		}
		if b, exists := status["podIP"]; exists {
			var text string
			if string(b) == "null" || json.Unmarshal(b, &text) != nil {
				return bad()
			}
			if text != "" {
				ip, err := netip.ParseAddr(text)
				if err != nil {
					return bad()
				}
				out.PrimaryIP = ip
			}
		}
		if b, exists := status["podIPs"]; exists {
			var addresses []map[string]json.RawMessage
			if string(b) == "null" || json.Unmarshal(b, &addresses) != nil || len(addresses) > 2 {
				return bad()
			}
			for _, fields := range addresses {
				var text string
				if json.Unmarshal(fields["ip"], &text) != nil {
					return bad()
				}
				ip, err := netip.ParseAddr(text)
				if err != nil {
					return bad()
				}
				out.PodIPs = append(out.PodIPs, ip)
			}
		}
	}
	return out, metadata, nil
}
