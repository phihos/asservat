package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type policyAttachFunc func(context.Context, authapp.PolicyGrantAttachmentInput) (authorization.PolicyGrantAttachment, bool, error)

func (f policyAttachFunc) AttachPolicyGrant(ctx context.Context, in authapp.PolicyGrantAttachmentInput) (authorization.PolicyGrantAttachment, bool, error) {
	return f(ctx, in)
}
func TestPolicyGrantAttachmentControlNeverReacceptsOrRenewsAuthority(t *testing.T) {
	f := newActivationFixture(t)
	original, err := f.activation().Activate(context.Background(), f, "restarts", "original-acceptance", true)
	if err != nil {
		t.Fatal(err)
	}
	authority := f.accepted[0].Authority
	f.status = value.PolicyStatus{PolicyUID: authority.PolicyUID, ActiveID: original.AcceptanceID, Authority: authority, MaxExecutions: authority.Limits.MaxExecutions, NotAfter: authority.NotAfter}
	service := f.activation()
	grant := "00000000-0000-4000-8000-000000000777"
	calls := 0
	var first authapp.PolicyGrantAttachmentInput
	service.GrantAttachments = policyAttachFunc(func(_ context.Context, in authapp.PolicyGrantAttachmentInput) (authorization.PolicyGrantAttachment, bool, error) {
		calls++
		if in.PolicyUID != authority.PolicyUID || in.GrantID != grant || in.Actor.Principal != f.author.Principal || in.IdempotencyKey != "attach-original" {
			t.Fatal("unbound control", in)
		}
		if calls == 1 {
			first = in
		} else if in.ID != first.ID {
			t.Fatal("retry replaced immutable receipt ID")
		}
		return authorization.PolicyGrantAttachment{ID: in.ID, PolicyUID: in.PolicyUID, AcceptanceID: original.AcceptanceID, GrantID: grant}, calls > 1, nil
	})
	for n := 0; n < 2; n++ {
		result, err := service.ActivateWithGrant(context.Background(), f, "restarts", "attach-original", false, grant)
		if err != nil || result.AcceptanceID != original.AcceptanceID || !result.NotAfter.Equal(authority.NotAfter) || result.MaxExecutions != authority.Limits.MaxExecutions || !result.Audited || result.Replay != (n > 0) || len(f.accepted) != 1 {
			t.Fatal("control renewed or replaced accepted policy", result, err, len(f.accepted))
		}
	}
	// An old control receipt must not make a deactivated acceptance active.
	f.status.ActiveID = ""
	if _, err := service.ActivateWithGrant(context.Background(), f, "restarts", "attach-original", false, grant); err == nil || calls != 2 {
		t.Fatal("deactivated policy replay acquired authority", err, calls)
	}
}
func TestPolicyGrantAttachmentControlRetainsFinalIdentityAndSourceDeadlines(t *testing.T) {
	for _, mode := range []string{"groups", "identity-expired", "source-expired", "store-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f := newActivationFixture(t)
			original, err := f.activation().Activate(context.Background(), f, "restarts", "original", true)
			if err != nil {
				t.Fatal(err)
			}
			f.status = value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: original.AcceptanceID, MaxExecutions: 10, NotAfter: original.NotAfter}
			service := f.activation()
			clock := f.now
			service.Now = func() time.Time { return clock }
			service.GrantAttachments = policyAttachFunc(func(_ context.Context, in authapp.PolicyGrantAttachmentInput) (authorization.PolicyGrantAttachment, bool, error) {
				switch mode {
				case "groups":
					f.author.Groups = []string{"unrelated"}
				case "identity-expired":
					f.author.ValidUntil = clock
				case "source-expired":
					clock = clock.Add(6 * time.Second)
				case "store-unavailable":
					return authorization.PolicyGrantAttachment{}, false, value.ErrUnavailable
				}
				return authorization.PolicyGrantAttachment{ID: in.ID, PolicyUID: in.PolicyUID, AcceptanceID: original.AcceptanceID, GrantID: in.GrantID}, false, nil
			})
			result, err := service.ActivateWithGrant(context.Background(), f, "restarts", "attach", false, "00000000-0000-4000-8000-000000000777")
			if err == nil || result.AcceptanceID != "" {
				t.Fatal("stale or unknown control returned protected success", result, err)
			}
			if mode == "groups" && !errors.Is(err, identity.ErrDenied) {
				t.Fatal(err)
			}
		})
	}
}
