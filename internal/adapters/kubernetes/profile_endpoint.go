package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"

	planner "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	plan "asservat.local/asservat/internal/domain/planning"
	value "asservat.local/asservat/internal/domain/targets"
)

// MaxProfileEndpoints bounds one cluster's profile endpoint entries; the
// planner refuses catalogs over 128 definitions.
const MaxProfileEndpoints = 64

// ProfileEndpointEntries validates and converts a cluster's administrator
// profile endpoint configuration (ADR-285). Each entry's source identity is
// derived from the cluster and its name, and its digest covers the entry's
// canonical public definition; no Secret, URL or credential is involved.
func ProfileEndpointEntries(clusterID string, in []contracts.RegionalProfileEndpoint) ([]planner.ProfileEndpointEntry, error) {
	if len(in) > MaxProfileEndpoints {
		return nil, value.ErrInvalid
	}
	names := map[string]bool{}
	out := make([]planner.ProfileEndpointEntry, 0, len(in))
	for _, e := range in {
		if !dnsLabel(e.Name) || names[e.Name] || len(e.Namespaces) > 64 {
			return nil, value.ErrInvalid
		}
		names[e.Name] = true
		for i, ns := range e.Namespaces {
			if !dnsLabel(ns) || slices.Contains(e.Namespaces[:i], ns) {
				return nil, value.ErrInvalid
			}
		}
		encoded, err := json.Marshal(e)
		if err != nil {
			return nil, value.ErrInvalid
		}
		digest := sha256.Sum256(encoded)
		id := sha256.Sum256([]byte("asservat-profile-endpoint/v1\x00" + clusterID + "\x00" + e.Name))
		id[6], id[8] = id[6]&0x0f|0x80, id[8]&0x3f|0x80 // RFC 9562 version 8, variant 10
		host := e.Host
		if host == "" {
			host = "localhost"
		}
		entry := planner.ProfileEndpointEntry{Namespaces: slices.Clone(e.Namespaces), Definition: plan.GoEndpointDefinition{
			Source:     plan.GoEndpointSource{ClusterID: clusterID, ResourceUID: fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16]), Name: e.Name, Digest: artifact.Digest(digest)},
			PathPolicy: plan.GoEndpointPathPolicy, Host: host, LoopbackFamily: e.LoopbackFamily}}
		switch e.Kind {
		case "template":
			if e.AddressMode != "" || e.Port != 0 {
				return nil, value.ErrInvalid
			}
			entry.Definition.AddressModes, entry.Definition.MinimumPort, entry.Definition.MaximumPort = slices.Clone(e.AddressModes), e.MinPort, e.MaxPort
		case "profile":
			if len(e.AddressModes) != 0 || e.MinPort != 0 || e.MaxPort != 0 {
				return nil, value.ErrInvalid
			}
			entry.Profile, entry.AddressMode, entry.Port = true, e.AddressMode, e.Port
			entry.Definition.AddressModes, entry.Definition.MinimumPort, entry.Definition.MaximumPort = []string{e.AddressMode}, e.Port, e.Port
		default:
			return nil, value.ErrInvalid
		}
		if !entry.Definition.Valid() {
			return nil, value.ErrInvalid
		}
		out = append(out, entry)
	}
	return out, nil
}

// ProfileEndpointsValid checks a cluster's configuration independently of
// its cluster ID (the installer validates before the cluster is known).
func ProfileEndpointsValid(in []contracts.RegionalProfileEndpoint) bool {
	_, err := ProfileEndpointEntries("00000000-0000-4000-8000-000000000001", in)
	return err == nil
}

// WithProfileEndpoints returns c resolving Go profile endpoints at preview
// through the cluster's administrator configuration; without it every
// resolution answers unsupported.
func (c *PodTargets) WithProfileEndpoints(in []contracts.RegionalProfileEndpoint) (*PodTargets, error) {
	if c == nil || c.client == nil {
		return nil, value.ErrInvalid
	}
	entries, err := ProfileEndpointEntries(c.client.clusterID, in)
	if err != nil {
		return nil, err
	}
	out := *c
	out.endpoints = entries
	return &out, nil
}

// ResolveProfileEndpoint answers one preview query (ADR-285): the exact
// Pod's routing declarations are observed once and resolved with the
// cluster's configuration. Nothing is dialed or probed and no Secret is read.
func (c *PodTargets) ResolveProfileEndpoint(ctx context.Context, r value.ProfileEndpointRequest) (value.ProfileEndpointResolution, error) {
	if c == nil || c.client == nil || ctx == nil || !r.Valid() || r.Target.ClusterID != c.client.clusterID {
		return value.ProfileEndpointResolution{}, value.ErrInvalid
	}
	if len(c.endpoints) == 0 {
		return value.ProfileEndpointResolution{}, value.ErrUnsupported
	}
	network, err := c.ObserveProfileNetwork(ctx, r.Target)
	if err != nil {
		return value.ProfileEndpointResolution{}, err
	}
	return planner.ResolveProfileEndpointRequest(c.endpoints, network, r, c.client.now())
}
