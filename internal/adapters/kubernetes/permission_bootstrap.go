package kubernetes

import (
	"context"
	"encoding/hex"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	value "asservat.local/asservat/internal/domain/configuration"
)

// BootstrapReviewClient reads one explicitly enrolled, administrator-protected
// installation ConfigMap. Kubernetes RBAC/installation qualification must deny
// its modification to permission delegates and application maintainers. A source
// cannot choose this name or declare its own review. No reviewer field grants
// permission-administrator rights.
type BootstrapReviewClient struct {
	client    *PermissionClient
	name, uid string
}

var _ port.BootstrapReviewReader = (*BootstrapReviewClient)(nil)

func NewBootstrapReviewClient(client *PermissionClient, name, uid string) (*BootstrapReviewClient, error) {
	if client == nil || !installationRefValid(name, uid) {
		return nil, value.ErrInvalid
	}
	return &BootstrapReviewClient{client, name, uid}, nil
}
func (c *BootstrapReviewClient) InitialPermissionReview(ctx context.Context) (value.BootstrapReview, error) {
	var out value.BootstrapReview
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.client.now()
	data, ref, err := c.client.installationConfig(ctx, c.name, c.uid)
	if err != nil {
		return out, err
	}
	if len(data) != 5 || data["format"] != "asservat-permission-bootstrap/v1" {
		return out, value.ErrInvalid
	}
	for _, v := range data {
		if len(v) > 256 {
			return out, value.ErrLimit
		}
	}
	reviewed, err := time.Parse(time.RFC3339Nano, data["reviewedAt"])
	if err != nil {
		return out, value.ErrInvalid
	}
	expires, err := time.Parse(time.RFC3339Nano, data["expiresAt"])
	if err != nil {
		return out, value.ErrInvalid
	}
	encoded, err := hex.DecodeString(data["bindingsSHA256"])
	if err != nil || len(encoded) != 32 {
		return out, value.ErrInvalid
	}
	out = value.BootstrapReview{Resource: ref, Reviewer: data["reviewer"], ReviewedAt: reviewed, ExpiresAt: expires, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}
	copy(out.BindingsDigest[:], encoded)
	if c.client.current(ctx, start, 5*time.Second) != nil || !out.Valid(c.client.now()) {
		return value.BootstrapReview{}, value.ErrChanged
	}
	return out, nil
}
