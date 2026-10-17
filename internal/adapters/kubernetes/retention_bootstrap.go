package kubernetes

import (
	"context"
	"encoding/hex"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	value "asservat.local/asservat/internal/domain/configuration"
)

// RetentionBootstrapReviewClient reads one independently enrolled installation
// object. Production installation must protect it from delegates, source and
// status writers. A retention CRD cannot select or self-attest this review.
type RetentionBootstrapReviewClient struct {
	client    *PermissionClient
	name, uid string
}

var _ port.RetentionBootstrapReviewReader = (*RetentionBootstrapReviewClient)(nil)

func NewRetentionBootstrapReviewClient(client *PermissionClient, name, uid string) (*RetentionBootstrapReviewClient, error) {
	if client == nil || !installationRefValid(name, uid) {
		return nil, value.ErrInvalid
	}
	return &RetentionBootstrapReviewClient{client, name, uid}, nil
}
func (c *RetentionBootstrapReviewClient) InitialRetentionReview(ctx context.Context) (value.RetentionBootstrapReview, error) {
	var out value.RetentionBootstrapReview
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.client.now()
	data, ref, err := c.client.installationConfig(ctx, c.name, c.uid)
	if err != nil {
		return out, err
	}
	if len(data) != 6 || data["format"] != "asservat-retention-bootstrap/v1" {
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
	policies, err := hex.DecodeString(data["policiesSHA256"])
	if err != nil || len(policies) != 32 {
		return out, value.ErrInvalid
	}
	protection, err := hex.DecodeString(data["protectionSHA256"])
	if err != nil || len(protection) != 32 {
		return out, value.ErrInvalid
	}
	out = value.RetentionBootstrapReview{Resource: ref, Reviewer: data["reviewer"], ReviewedAt: reviewed, ExpiresAt: expires, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}
	copy(out.PoliciesDigest[:], policies)
	copy(out.ProtectionDigest[:], protection)
	if c.client.current(ctx, start, 5*time.Second) != nil || !out.Valid(c.client.now()) {
		return value.RetentionBootstrapReview{}, value.ErrChanged
	}
	return out, nil
}
