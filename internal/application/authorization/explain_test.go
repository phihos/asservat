package authorization

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

type explainFixture struct {
	now                  time.Time
	caller               identity.Identity
	resolved             targets.PodResolution
	projection           value.Projection
	targetErr, permErr   error
	recovery             artifact.RecoveryProof
	permissionReads      int
	identityChangesFinal bool
	identityResolutions  int
}

func (f *explainFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	f.identityResolutions++
	i := f.caller
	if f.identityChangesFinal && f.identityResolutions > 1 {
		i.Principal.Subject = "someone-else"
	}
	return i, nil
}
func (f *explainFixture) ResolveWorkload(context.Context, targets.WorkloadRequest) (targets.PodResolution, error) {
	return f.resolved, f.targetErr
}
func (f *explainFixture) Permissions(_ context.Context, t value.Target) (value.Projection, error) {
	f.permissionReads++
	if t != f.projection.Target {
		return value.Projection{}, errors.New("unexpected target")
	}
	return f.projection, f.permErr
}
func (f *explainFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, nil
}

const explainInstallation = "11111111-2222-4333-8444-555555555555"

func newExplainFixture() (*explainFixture, AccessExplainer) {
	n := time.Now().UTC()
	f := &explainFixture{now: n}
	rev := identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}
	f.caller = identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}, Scopes: []string{"evidence:read"}, Groups: []string{"team-a"}, Policy: rev, VerifiedAt: n, ValidUntil: n.Add(30 * time.Second)}
	f.resolved = targets.PodResolution{Request: targets.Request{ClusterID: "22222222-3333-4444-8555-666666666666", Namespace: configuration.NamespaceRef{Name: "payments", UID: "ns"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "deployment"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "ns", Name: "api-a", UID: "pod", NodeName: "worker", ControllerUID: "rs"}, NodeUID: "node", NodeBootID: "33333333-4444-4555-8666-777777777777", PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
	a := artifact.AudienceAssignment{Kind: "Group", Issuer: f.caller.Principal.Issuer, SubjectID: "team-a", Role: "evidence-reader", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: "44444444-5555-4666-8777-888888888888", BasisDigest: artifact.Digest{2}}
	f.projection = value.Projection{Target: f.resolved.Target(), Revision: rev, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: n, DeniesFreshUntil: n.Add(30 * time.Second), Allows: []value.CurrentAssignment{{Audience: a, ObservedAt: n, FreshUntil: n.Add(30 * time.Second)}}}
	f.recovery = artifact.RecoveryProof{InstallationID: explainInstallation, IssuerEpoch: explainInstallation, Revision: rev, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
	return f, AccessExplainer{InstallationID: explainInstallation, Targets: f, Permissions: f, Recovery: f, Now: func() time.Time { return f.now }}
}

var explainRef = targets.WorkloadRequest{ClusterID: "22222222-3333-4444-8555-666666666666", Namespace: "payments", Kind: "Deployment", Name: "api"}

func TestAccessExplainerRunsEvaluatorOnResolvedTarget(t *testing.T) {
	f, s := newExplainFixture()
	got, until, err := s.Explain(context.Background(), f, explainRef, value.ReadApproved)
	if err != nil || got.Decision != value.Allow || !got.Disclosed || got.Target != f.resolved.Target() || len(got.Assignments) != 1 {
		t.Fatalf("got %+v err=%v", got, err)
	}
	if until.After(f.recovery.FreshUntil) || until.After(f.caller.ValidUntil) {
		t.Fatalf("reply deadline %v exceeds recovery/identity", until)
	}
	got, _, err = s.Explain(context.Background(), f, explainRef, value.CollectContext)
	if err != nil || got.Decision != value.Deny || got.Unmet != value.UnmetClientScope || got.MissingScope != "evidence:capture" {
		t.Fatalf("capture without scope: %+v err=%v", got, err)
	}
}

func TestAccessExplainerUnresolvedTargetIsUniform(t *testing.T) {
	for _, e := range []error{targets.ErrUnavailable, targets.ErrDenied, targets.ErrUnsupported} {
		f, s := newExplainFixture()
		f.targetErr = e
		got, _, err := s.Explain(context.Background(), f, explainRef, value.ReadApproved)
		if err != nil || got.Disclosed || got.Decision != value.Deny || got.Unmet != value.UnmetNoMatchingAllow || f.permissionReads != 0 {
			t.Fatalf("%v: got %+v err=%v reads=%d", e, got, err, f.permissionReads)
		}
	}
}

func TestAccessExplainerUnavailableIsIndeterminate(t *testing.T) {
	f, s := newExplainFixture()
	f.recovery.InstallationID = "99999999-2222-4333-8444-555555555555"
	if got, _, err := s.Explain(context.Background(), f, explainRef, value.ReadApproved); err != nil || got.Decision != value.Indeterminate || got.Disclosed {
		t.Fatalf("recovery: %+v err=%v", got, err)
	}
	f, s = newExplainFixture()
	f.permErr = errors.New("sql")
	if got, _, err := s.Explain(context.Background(), f, explainRef, value.ReadApproved); err != nil || got.Decision != value.Indeterminate || got.Disclosed {
		t.Fatalf("permissions: %+v err=%v", got, err)
	}
}

func TestAccessExplainerRechecksCaller(t *testing.T) {
	f, s := newExplainFixture()
	f.identityChangesFinal = true
	if _, _, err := s.Explain(context.Background(), f, explainRef, value.ReadApproved); !errors.Is(err, identity.ErrDenied) {
		t.Fatalf("changed caller accepted: %v", err)
	}
	f, s = newExplainFixture()
	if _, _, err := s.Explain(context.Background(), f, targets.WorkloadRequest{}, value.ReadApproved); !errors.Is(err, value.ErrExplainInvalid) {
		t.Fatalf("invalid ref: %v", err)
	}
}
