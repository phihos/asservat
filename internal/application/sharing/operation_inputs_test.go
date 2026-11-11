package sharing

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
)

type observedOperationStore struct {
	Store
	creates   []Request
	transfers []Transfer
	revokes   []Revocation
}

func (s *observedOperationStore) CreateShare(ctx context.Context, in Request, recovery artifact.RecoveryProof) (value.Share, bool, error) {
	s.creates = append(s.creates, in)
	return s.Store.CreateShare(ctx, in, recovery)
}
func (s *observedOperationStore) TransferShare(ctx context.Context, in Transfer, recovery artifact.RecoveryProof) (value.Share, bool, error) {
	s.transfers = append(s.transfers, in)
	return s.Store.TransferShare(ctx, in, recovery)
}
func (s *observedOperationStore) RevokeShare(ctx context.Context, in Revocation, recovery artifact.RecoveryProof) (value.Share, bool, error) {
	s.revokes = append(s.revokes, in)
	return s.Store.RevokeShare(ctx, in, recovery)
}

// Every public invocation has another paid audit operation. That private ID
// must reach storage without changing the business request or renewing a share.
func TestShareBusinessReplayAcrossPaidOperations(t *testing.T) {
	f, service := newFixture()
	store := &observedOperationStore{Store: service.Store}
	service.Store = store
	input := f.input("create")
	input.OperationID = testID(901)
	created, _, err := service.Create(t.Context(), f, input)
	if err != nil {
		t.Fatal(err)
	}
	input.OperationID = testID(902)
	again, replay, err := service.Create(t.Context(), f, input)
	if err != nil || !replay || again.ID != created.ID || !again.ExpiresAt.Equal(created.ExpiresAt) || len(f.store.created) != 1 ||
		len(store.creates) != 2 || store.creates[0].OperationID != testID(901) || store.creates[1].OperationID != testID(902) || store.creates[0].RequestDigest != store.creates[1].RequestDigest {
		t.Fatal("a new paid operation changed create replay or did not reach storage", err)
	}
	transfer := TransferInput{OperationID: testID(903), ShareID: created.ID, ExpectedRevision: 1, IdempotencyKey: "transfer", Management: value.ManagementRequest{Mode: "teams", Teams: []string{"owners"}}}
	moved, _, err := service.Transfer(t.Context(), f, transfer)
	if err != nil {
		t.Fatal(err)
	}
	transfer.OperationID = testID(904)
	again, replay, err = service.Transfer(t.Context(), f, transfer)
	if err != nil || !replay || again.Revision != moved.Revision || !again.ExpiresAt.Equal(created.ExpiresAt) || len(store.transfers) != 2 ||
		store.transfers[0].OperationID != testID(903) || store.transfers[1].OperationID != testID(904) || store.transfers[0].RequestDigest != store.transfers[1].RequestDigest {
		t.Fatal("a new paid operation changed transfer replay or did not reach storage", err)
	}
	revoke := RevokeInput{OperationID: testID(905), ShareID: created.ID, ExpectedRevision: moved.Revision, IdempotencyKey: "revoke"}
	revoked, _, err := service.Revoke(t.Context(), f, revoke)
	if err != nil {
		t.Fatal(err)
	}
	revoke.OperationID = testID(906)
	again, replay, err = service.Revoke(t.Context(), f, revoke)
	if err != nil || !replay || again.Revision != revoked.Revision || !again.RevokedAt.Equal(revoked.RevokedAt) || len(store.revokes) != 2 ||
		store.revokes[0].OperationID != testID(905) || store.revokes[1].OperationID != testID(906) {
		t.Fatal("a new paid operation changed revocation replay or did not reach storage", err)
	}
}

type observedPolicyOperations struct {
	policy  PolicySharing
	changes []PolicyRevocation
}

func (s *observedPolicyOperations) PolicySharing(context.Context, string) (PolicySharing, error) {
	return s.policy, nil
}
func (s *observedPolicyOperations) RevokePolicySharing(_ context.Context, in PolicyRevocation, _ artifact.RecoveryProof) (int, bool, error) {
	s.changes = append(s.changes, in)
	return 2, len(s.changes) > 1, nil
}
func (s *observedPolicyOperations) StopPolicySharing(_ context.Context, in PolicyRevocation, _ artifact.RecoveryProof) (bool, error) {
	s.changes = append(s.changes, in)
	return len(s.changes) > 1, nil
}

func TestPolicySharingMutationsCarryPaidOperation(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(map[bool]string{false: "revoke", true: "stop"}[stop], func(t *testing.T) {
			f, service := newFixture()
			instruction := capture.PolicyShareInstruction{Creator: f.i.Principal, Management: []artifact.AudienceAssignment{f.p.Allows[1].Audience},
				Recipients: []value.ShareRecipient{{Kind: "Group", Issuer: f.i.Principal.Issuer, ID: "outsiders"}}, MaxCaptures: 2, NotAfter: f.record.Retained.Effective.ExpiresAt}
			if !instruction.Valid() {
				t.Fatal("invalid synthetic policy instruction")
			}
			store := &observedPolicyOperations{policy: PolicySharing{AcceptanceID: testID(80), Instruction: instruction, Target: f.p.Target}}
			service.Policies = store
			change := service.RevokePolicySharing
			if stop {
				change = service.StopPolicySharing
			}
			input := PolicyRevokeInput{OperationID: testID(901), AcceptanceID: store.policy.AcceptanceID, ExpectedRevision: 1, IdempotencyKey: "stable-business-key"}
			if _, err := change(t.Context(), f, input); err != nil {
				t.Fatal(err)
			}
			input.OperationID = testID(902)
			if receipt, err := change(t.Context(), f, input); err != nil || !receipt.Replay || len(store.changes) != 2 ||
				store.changes[0].OperationID != testID(901) || store.changes[1].OperationID != testID(902) ||
				store.changes[0].IdempotencyKey != store.changes[1].IdempotencyKey || store.changes[0].ExpectedRevision != store.changes[1].ExpectedRevision {
				t.Fatal("policy mutation lost its current paid operation or changed business replay", err)
			}
		})
	}
}
