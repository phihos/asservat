package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/json"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// PolicyGrantAttachmentInput is one explicit activate_policy control after its
// existing encrypted intent acknowledgement. This receipt is idempotency state,
// not durable audit, a new acceptance, or independently issued authority.
type PolicyGrantAttachmentInput struct {
	ID, PolicyUID, GrantID, IdempotencyKey string
	Actor                                  identity.Identity
	Recovery                               artifact.RecoveryProof
}

type PolicyGrantAttachmentStore interface {
	AttachPolicyGrant(context.Context, PolicyGrantAttachmentInput) (value.PolicyGrantAttachment, bool, error)
}

// Current groups, freshness and settings are checked at use, never included in
// the original caller-input identity. Replay cannot change the attached grant.
func PolicyGrantAttachmentDigest(in PolicyGrantAttachmentInput) artifact.Digest {
	b, _ := json.Marshal(struct {
		Format             string
		Actor              identity.Principal
		PolicyUID, GrantID string
	}{"policy-grant-attachment/v1", in.Actor.Principal, in.PolicyUID, in.GrantID})
	return sha256.Sum256(b)
}
