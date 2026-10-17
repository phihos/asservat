package kubernetes

import (
	"context"
	"encoding/base64"
	"time"

	port "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// WorkTrustClient reads a pinned installation-owned ConfigMap. Its protection,
// accepted issuer epoch and receiver enrollment are independent bootstrap facts.
// A key ID or command field can never select an API object or remote key URL.
type WorkTrustClient struct {
	client    *PermissionClient
	name, uid string
}

var _ port.WorkTrustReader = (*WorkTrustClient)(nil)

func NewWorkTrustClient(client *PermissionClient, name, uid string) (*WorkTrustClient, error) {
	if client == nil || !installationRefValid(name, uid) {
		return nil, value.ErrInvalid
	}
	return &WorkTrustClient{client: client, name: name, uid: uid}, nil
}

func (c *WorkTrustClient) WorkTrust(ctx context.Context, r value.Receiver) (value.WorkTrust, error) {
	var out value.WorkTrust
	start := c.client.now()
	if !r.Valid(start) || r.ClusterID != c.client.clusterID {
		return out, value.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	data, ref, err := c.client.installationConfig(ctx, c.name, c.uid)
	if err != nil || len(data) != 1 || data["work-trust.json"] == "" {
		return out, value.ErrUnavailable
	}
	var wire contracts.WorkTrustSettings
	digest, err := decodePermissionSpec([]byte(data["work-trust.json"]), c.client.validator.workTrustSchema, &wire)
	if err != nil || wire.ClusterID != r.ClusterID || wire.IssuerEpoch != r.IssuerEpoch {
		return out, value.ErrDenied
	}
	out = value.WorkTrust{Revision: identity.Revision{UID: ref.UID, Generation: wire.Revision, Digest: digest}, ObservedAt: start, FreshUntil: start.Add(30 * time.Second)}
	for _, k := range wire.Keys {
		key, err := base64.RawURLEncoding.Strict().DecodeString(k.PublicKey)
		if err != nil || len(key) != 32 || base64.RawURLEncoding.EncodeToString(key) != k.PublicKey {
			return value.WorkTrust{}, value.ErrInvalid
		}
		before, e1 := time.Parse(time.RFC3339Nano, k.NotBefore)
		after, e2 := time.Parse(time.RFC3339Nano, k.NotAfter)
		if e1 != nil || e2 != nil || before.UTC().Format(time.RFC3339Nano) != k.NotBefore || after.UTC().Format(time.RFC3339Nano) != k.NotAfter {
			return value.WorkTrust{}, value.ErrInvalid
		}
		out.Keys = append(out.Keys, value.WorkKey{ID: k.ID, ClusterID: r.ClusterID, IssuerEpoch: r.IssuerEpoch, PublicKey: key, NotBefore: before, NotAfter: after})
	}
	if c.client.current(ctx, start, 5*time.Second) != nil || !out.Valid(c.client.now()) || !r.Valid(c.client.now()) {
		return value.WorkTrust{}, value.ErrUnavailable
	}
	return out, nil
}
