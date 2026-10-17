package audit

import (
	"context"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/audit"
)

type profileFixture struct {
	normal value.OperationLifecyclePolicy
}

func (f *profileFixture) ReadCapacityAuditProfiles(context.Context) (value.AcceptedCapacityAuditProfiles, error) {
	return value.AcceptedCapacityAuditProfiles{Normal: value.CapacityAuditProfile{Policy: f.normal}}, nil
}

// ADR-190: Begin uses the current accepted profile; Finish keeps the policy
// its own Begin used even after the hub-worker renewed the profile, and an
// unknown intent fails closed.
func TestSelectedAuditorBindsBeginPolicyThroughFinish(t *testing.T) {
	in := auditIntent()
	original := healthyPolicy(in)
	profiles := &profileFixture{normal: original}
	f := &healthyFixture{operationFixture: &operationFixture{}}
	var built []value.OperationLifecyclePolicy
	s, err := NewSelectedOperationAuditor("normal", profiles, func(_ context.Context, p value.OperationLifecyclePolicy) (*HealthyOperationAuditor, error) {
		built = append(built, p)
		return NewHealthyOperationAuditor(p, f, f, f, f, f, func() time.Time { return in.CreatedAt })
	})
	if err != nil || !s.Configured() {
		t.Fatal(err)
	}
	if err = s.Begin(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	renewed := original
	renewed.BackingRevision, renewed.ValidUntil = 2, original.ValidUntil.Add(time.Hour)
	profiles.normal = renewed
	if err = s.Finish(context.Background(), auditOutcome(in)); err != nil {
		t.Fatal("finish with the begun policy", err)
	}
	if len(built) != 1 || f.snap.Outcome.Intent.Lifecycle == nil || f.snap.Outcome.Intent.Lifecycle.Policy.BackingRevision != 1 {
		t.Fatal("finish rebound the operation to a renewed profile", len(built))
	}
	unknown := auditIntent()
	unknown.ID = "00000000-0000-4000-8000-000000000009"
	if s.Finish(context.Background(), auditOutcome(unknown)) == nil {
		t.Fatal("finished an intent this process never began")
	}
	if _, err = NewSelectedOperationAuditor("capture", profiles, func(context.Context, value.OperationLifecyclePolicy) (*HealthyOperationAuditor, error) {
		return nil, nil
	}); err == nil {
		t.Fatal("accepted a lane without accepted profiles")
	}
}
