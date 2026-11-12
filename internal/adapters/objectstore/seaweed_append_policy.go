package objectstore

import (
	"context"
	"encoding/json"
	"slices"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// AppendBucketPolicy extends only the original completed bucket. The caller
// supplies independently compiled additions and serializes trusted provider
// administration. Existing statements retain their original SIDs and contents.
// No bucket creation, versioning repair, replacement or concurrent-admin merge
// is introduced: ConfigureBucket independently checks the original source again.
func (s *SeaweedSetup) AppendBucketPolicy(ctx context.Context, claim contracts.SeaweedBucketInitialization, additions json.RawMessage) error {
	if !s.validClaim(claim) || claim.Pending || ctx == nil || ctx.Err() != nil || len(additions) == 0 || len(additions) > providerconfig.SeaweedConfigLimit {
		return storageAnswer{"append-input"}
	}
	extra, err := seaweedPolicyStatements(additions)
	if err != nil {
		return storageAnswer{"append-policy"}
	}
	old, err := s.store.client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: &claim.Bucket})
	if err != nil || old == nil || old.Policy == nil || len(*old.Policy) > providerconfig.SeaweedConfigLimit || ctx.Err() != nil {
		return storageAnswer{"append-original-policy"}
	}
	retained, err := seaweedPolicyStatements([]byte(*old.Policy))
	if err != nil {
		return storageAnswer{"append-original-policy"}
	}
	for sid, statement := range extra {
		if previous, exists := retained[sid]; exists {
			if !sameSeaweedJSON(previous, statement) {
				return storageAnswer{"append-conflict"}
			}
		} else {
			retained[sid] = statement
		}
	}
	sids := make([]string, 0, len(retained))
	for sid := range retained {
		sids = append(sids, sid)
	}
	slices.Sort(sids)
	statements := make([]json.RawMessage, 0, len(sids))
	for _, sid := range sids {
		statements = append(statements, retained[sid])
	}
	merged, err := json.Marshal(struct {
		Version   string            `json:"Version"`
		Statement []json.RawMessage `json:"Statement"`
	}{"2012-10-17", statements})
	if err != nil {
		return storageAnswer{"append-policy"}
	}
	return s.ConfigureBucket(ctx, claim, merged)
}
