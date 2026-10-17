package authorization

import (
	"context"
	"testing"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/identity"
)

type changingIdentity struct {
	*fixture
	calls, changeAt int
}

func (r *changingIdentity) Resolve(ctx context.Context, token string) (value.Identity, error) {
	r.calls++
	i, err := r.fixture.Resolve(ctx, token)
	if r.calls == r.changeAt {
		i.Groups = []string{"removed-from-team"}
	}
	return i, err
}

func TestSharedCurrentIdentityRechecksCaptureAndReadAfterBlockingWork(t *testing.T) {
	for _, capture := range []bool{false, true} {
		for _, revoke := range []bool{false, true} {
			f, service, request := newFixture()
			f.i.Scopes = append(f.i.Scopes, "evidence:capture")
			r := &changingIdentity{fixture: f}
			if revoke {
				r.changeAt = 3 // bind, initial authorization, final authorization
			}
			current, _, err := identities.NewBearerRequest(context.Background(), r, "synthetic-token", service.Now)
			if err != nil {
				t.Fatal(err)
			}
			service.Identities = nil // no bearer fallback in the shared path
			var eligible bool
			if capture {
				eligible = service.ContextEligibilityCurrent(context.Background(), current, request.Target).Eligible
			} else {
				eligible = service.EligibilityCurrent(context.Background(), current, request).Eligible
			}
			if eligible == revoke || r.calls != 3 {
				t.Fatalf("capture=%v revoked=%v eligible=%v identity reads=%d", capture, revoke, eligible, r.calls)
			}
		}
	}
}

func TestSharedCurrentDownloadIdentityPreservesExistingPolicyEvaluation(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		f, service, scope := newDownloadAuthorityFixture()
		r := &changingIdentity{fixture: f.fixture}
		if revoke {
			r.changeAt = 3
		}
		current, _, err := identities.NewBearerRequest(context.Background(), r, "synthetic-token", service.Now)
		if err != nil {
			t.Fatal(err)
		}
		service.Identities = nil
		out, err := service.CheckDownloadCurrent(context.Background(), current, scope)
		if revoke {
			if err == nil {
				t.Fatal("revoked current request permitted native delivery")
			}
		} else if err != nil || !out.Valid(f.now) || out.Scope != scope {
			t.Fatal("current-identity native policy differs from existing evaluator", err)
		}
	}
}
