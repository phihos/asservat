package kubernetes

import (
	"context"
	"encoding/hex"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// RetentionTopologyClient reads an independently accepted immutable topology.
// Installation bootstrap supplies the exact namespace/object/content pins from
// its protected enrollment configuration. Neither a request nor this reader can
// discover or accept replacement pins, enroll a target or clear recovery.
type RetentionTopologyClient struct {
	client                  *PermissionClient
	name, uid, root, target string
	digest                  artifact.Digest
}

var _ port.RetentionTopologyReader = (*RetentionTopologyClient)(nil)

// RetentionTopologyPin is supplied only by protected installation/enrollment
// composition. Copies of request parameters must never populate this table.
type RetentionTopologyPin struct {
	TargetClusterID, Name, UID string
	ContentDigest              artifact.Digest
}
type RetentionTopologies struct {
	readers map[string]*RetentionTopologyClient
}

var _ port.RetentionTopologyReader = (*RetentionTopologies)(nil)

func NewRetentionTopologies(client *PermissionClient, root string, pins []RetentionTopologyPin) (*RetentionTopologies, error) {
	// An empty set (ADR-194 D3) denies every target; callers bound the minimum.
	if pins == nil || len(pins) > 1024 {
		return nil, value.ErrInvalid
	}
	out := &RetentionTopologies{readers: make(map[string]*RetentionTopologyClient, len(pins))}
	names := map[string]bool{}
	for _, p := range pins {
		if out.readers[p.TargetClusterID] != nil || names[p.Name] {
			return nil, value.ErrInvalid
		}
		r, err := NewRetentionTopologyClient(client, p.Name, p.UID, root, p.TargetClusterID, p.ContentDigest)
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

func NewRetentionTopologyClient(client *PermissionClient, name, uid, root, target string, digest artifact.Digest) (*RetentionTopologyClient, error) {
	if client == nil || !installationRefValid(name, uid) || !authorization.UUID(root) || !authorization.UUID(target) || digest == (artifact.Digest{}) {
		return nil, value.ErrInvalid
	}
	return &RetentionTopologyClient{client: client, name: name, uid: uid, root: root, target: target, digest: digest}, nil
}
func (c *RetentionTopologyClient) RetentionTopology(ctx context.Context, target string) (privacy.PolicyTopology, error) {
	var out privacy.PolicyTopology
	if target != c.target {
		return out, value.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.client.now()
	data, ref, err := c.client.installationConfigMode(ctx, c.name, c.uid, true)
	if err != nil {
		return out, err
	}
	if len(data) != 1 || data["topology.json"] == "" {
		return out, value.ErrInvalid
	}
	var wire contracts.RetentionTopologySettings
	digest, err := decodePermissionSpec([]byte(data["topology.json"]), c.client.validator.retentionTopologySchema, &wire)
	if err != nil || digest != c.digest || wire.RootID != c.root || wire.TargetClusterID != c.target {
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
	out = privacy.PolicyTopology{RootID: c.root, TargetClusterID: c.target, Revision: identity.Revision{UID: ref.UID, Generation: wire.Revision, Digest: digest}, Sources: []privacy.PolicySourceRef{hub}, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}
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
	return out, nil
}
