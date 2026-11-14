package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"k8s.io/apimachinery/pkg/util/validation"
)

// RetentionTopologyClient reads the named immutable topology ConfigMap of one
// target under ordinary RBAC (Helm-native: no UID or content pins). Neither a
// request nor this reader can enroll a target or clear recovery.
type RetentionTopologyClient struct {
	client             *PermissionClient
	name, root, target string
	// ponytail: one process-wide reuse of the last successful pinned read;
	// failures are never kept. Per-target lock serializes cold reads.
	mu   sync.Mutex
	last privacy.PolicyTopology
}

var _ port.RetentionTopologyReader = (*RetentionTopologyClient)(nil)

// RetentionTopologyPin names one target's topology ConfigMap, from the
// installation configuration or the cluster catalog, never from a request.
type RetentionTopologyPin struct {
	TargetClusterID, Name string
}
type RetentionTopologies struct {
	readers map[string]port.RetentionTopologyReader
}

var _ port.RetentionTopologyReader = (*RetentionTopologies)(nil)

func NewRetentionTopologies(client *PermissionClient, root string, pins []RetentionTopologyPin) (*RetentionTopologies, error) {
	// An empty set (ADR-194 D3) denies every target; callers bound the minimum.
	if pins == nil || len(pins) > 1024 {
		return nil, value.ErrInvalid
	}
	out := &RetentionTopologies{readers: make(map[string]port.RetentionTopologyReader, len(pins))}
	names := map[string]bool{}
	for _, p := range pins {
		if out.readers[p.TargetClusterID] != nil || names[p.Name] {
			return nil, value.ErrInvalid
		}
		r, err := NewRetentionTopologyClient(client, p.Name, root, p.TargetClusterID)
		if err != nil {
			return nil, err
		}
		out.readers[p.TargetClusterID] = r
		names[p.Name] = true
	}
	return out, nil
}
func (r *RetentionTopologies) RetentionTopology(ctx context.Context, target string) (privacy.PolicyTopology, error) {
	reader := r.readers[target]
	if reader == nil {
		return privacy.PolicyTopology{}, value.ErrDenied
	}
	return reader.RetentionTopology(ctx, target)
}

// AddHubTopology serves the hub cluster's own topology in process
// (mode=combined): its only source is the hub retention source the hub-worker
// observes in the release namespace (contracts.RetentionSourceDigest). A
// ConfigMap pin for the same target is refused.
func (r *RetentionTopologies) AddHubTopology(client *PermissionClient, root string) error {
	if r == nil || client == nil || !authorization.UUID(root) || r.readers[client.clusterID] != nil {
		return value.ErrInvalid
	}
	hub := privacy.PolicySourceRef{ClusterID: client.clusterID, ControlNamespaceUID: client.control.UID, Hub: true, ProtectionDigest: artifact.Digest(contracts.RetentionSourceDigest(client.clusterID, client.control.Name))}
	if !port.ValidRetentionSource(hub) {
		return value.ErrInvalid
	}
	r.readers[client.clusterID] = hubTopology{client: client, root: root, hub: hub}
	return nil
}

type hubTopology struct {
	client *PermissionClient
	root   string
	hub    privacy.PolicySourceRef
}

func (h hubTopology) RetentionTopology(ctx context.Context, target string) (privacy.PolicyTopology, error) {
	if ctx == nil || ctx.Err() != nil || target != h.client.clusterID {
		return privacy.PolicyTopology{}, value.ErrDenied
	}
	start := h.client.now()
	digest := sha256.Sum256([]byte("asservat-hub-topology/v1\x00" + h.root + "\x00" + h.client.clusterID + "\x00" + h.client.control.UID))
	out := privacy.PolicyTopology{RootID: h.root, TargetClusterID: target, Revision: identity.Revision{UID: h.client.control.UID, Generation: 1, Digest: digest}, Sources: []privacy.PolicySourceRef{h.hub}, ObservedAt: start, FreshUntil: start.Add(privacy.PolicyTopologyInterval)}
	if !out.Valid(h.client.now()) {
		return privacy.PolicyTopology{}, value.ErrUnavailable
	}
	return out, nil
}

func NewRetentionTopologyClient(client *PermissionClient, name, root, target string) (*RetentionTopologyClient, error) {
	if client == nil || len(validation.IsDNS1123Subdomain(name)) != 0 || !authorization.UUID(root) || !authorization.UUID(target) {
		return nil, value.ErrInvalid
	}
	return &RetentionTopologyClient{client: client, name: name, root: root, target: target}, nil
}
func (c *RetentionTopologyClient) RetentionTopology(ctx context.Context, target string) (privacy.PolicyTopology, error) {
	var out privacy.PolicyTopology
	if target != c.target {
		return out, value.ErrDenied
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// The cached observation is used to its end only while it still covers an
	// evidence-read request; nearer its end it is re-read on demand (installed
	// native86: an approved read was cut by this observation 1.27 s after its
	// authority check). A failed early re-read keeps the still-current
	// observation and its original end unless the configuration changed.
	n := c.client.now()
	cached := c.last.Valid(n) && n.Before(c.last.FreshUntil)
	if cached && c.last.FreshUntil.Sub(n) >= identity.EvidenceReadRequestWindow {
		out = c.last
		out.Sources = slices.Clone(c.last.Sources)
		return out, nil
	}
	out, err := c.readTopology(ctx)
	if err != nil && cached && !errors.Is(err, value.ErrChanged) && !errors.Is(err, value.ErrInvalid) && !errors.Is(err, value.ErrDenied) && c.client.now().Before(c.last.FreshUntil) {
		out = c.last
		out.Sources = slices.Clone(c.last.Sources)
		return out, nil
	}
	return out, err
}

func (c *RetentionTopologyClient) readTopology(ctx context.Context) (privacy.PolicyTopology, error) {
	var out privacy.PolicyTopology
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.client.now()
	uid, err := ObjectUIDFrom(ctx, c.client, "/api/v1/namespaces/"+c.client.control.Name+"/configmaps/"+c.name)
	if err != nil {
		return out, err
	}
	data, ref, err := c.client.installationConfigMode(ctx, c.name, uid, true)
	if err != nil {
		return out, err
	}
	if len(data) != 1 || data["topology.json"] == "" {
		return out, value.ErrInvalid
	}
	var wire contracts.RetentionTopologySettings
	digest, err := decodePermissionSpec([]byte(data["topology.json"]), c.client.validator.retentionTopologySchema, &wire)
	if err != nil || wire.RootID != c.root || wire.TargetClusterID != c.target {
		return out, value.ErrChanged
	}
	source := func(w contracts.RetentionPolicySource, hub bool) (privacy.PolicySourceRef, error) {
		p := privacy.PolicySourceRef{ClusterID: w.ClusterID, ControlNamespaceUID: w.ControlNamespaceUID, Hub: hub}
		b, err := hex.DecodeString(w.ProtectionSHA256)
		if err != nil || len(b) != 32 {
			return p, value.ErrInvalid
		}
		copy(p.ProtectionDigest[:], b)
		if !port.ValidRetentionSource(p) {
			return privacy.PolicySourceRef{}, value.ErrInvalid
		}
		return p, nil
	}
	hub, err := source(wire.Hub, true)
	if err != nil {
		return out, err
	}
	out = privacy.PolicyTopology{RootID: c.root, TargetClusterID: c.target, Revision: identity.Revision{UID: ref.UID, Generation: wire.Revision, Digest: digest}, Sources: []privacy.PolicySourceRef{hub}, ObservedAt: start, FreshUntil: start.Add(privacy.PolicyTopologyInterval)}
	if wire.Local != nil {
		local, err := source(*wire.Local, false)
		if err != nil {
			return privacy.PolicyTopology{}, err
		}
		out.Sources = append(out.Sources, local)
	}
	if c.client.current(ctx, start, 5*time.Second) != nil || !out.Valid(c.client.now()) {
		return privacy.PolicyTopology{}, value.ErrUnavailable
	}
	c.last = out
	c.last.Sources = slices.Clone(out.Sources)
	return out, nil
}
