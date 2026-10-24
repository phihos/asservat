package authorization

import (
	"context"
	"errors"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type queryEnvironmentFixture struct {
	now        time.Time
	policy     value.ContextProjectionPolicy
	recovery   artifact.RecoveryProof
	processing artifact.DownloadProcessingProof
	count      map[string]int
	on         func(context.Context, string, int)
	fail       string
}

func (f *queryEnvironmentFixture) step(ctx context.Context, name string) error {
	f.count[name]++
	if f.on != nil {
		f.on(ctx, name, f.count[name])
	}
	if f.fail == name {
		return errors.New("private source details")
	}
	return ctx.Err()
}
func (f *queryEnvironmentFixture) ContextProjectionPolicy(ctx context.Context, target, store string) (value.ContextProjectionPolicy, error) {
	if target != f.policy.Path.TargetClusterID || store != f.policy.Path.StoreID {
		return value.ContextProjectionPolicy{}, value.ErrUnavailable
	}
	e := f.step(ctx, "policy")
	return f.policy, e
}
func (f *queryEnvironmentFixture) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	e := f.step(ctx, "recovery")
	return f.recovery, e
}
func (f *queryEnvironmentFixture) ContextProjectionProcessing(ctx context.Context, r ContextProjectionEvidence, p artifact.RecoveryProof) (artifact.DownloadProcessingProof, error) {
	e := f.step(ctx, "processing")
	if r.CaptureID != f.processing.CaptureID || p.IssuerEpoch != f.recovery.IssuerEpoch {
		return artifact.DownloadProcessingProof{}, value.ErrUnavailable
	}
	return f.processing, e
}

func newQueryEnvironmentFixture() (*queryEnvironmentFixture, CurrentProjectionEnvironment, ContextProjectionEvidence, identity.Principal) {
	base, _, scope := newProjectionFixture()
	e := base.environment
	f := &queryEnvironmentFixture{now: base.now, policy: value.ContextProjectionPolicy{RootID: scope.RootID, InstallationID: e.InstallationID, RecoveryEpoch: e.Recovery.IssuerEpoch, Revision: e.PolicyRevision, ProtectionDigest: artifact.Digest{2}, Path: e.Path, PermittedRegions: []string{"region"}, Clients: []value.ContextProjectionClient{{Issuer: scope.Principal.Issuer, ID: scope.Principal.ClientID, Kind: scope.Principal.Kind, Purposes: []string{base.record.PurposeRef}}}, ObservedAt: base.now, FreshUntil: base.now.Add(5 * time.Second)}, recovery: e.Recovery, processing: e.Processing, count: map[string]int{}}
	return f, CurrentProjectionEnvironment{RootID: scope.RootID, InstallationID: e.InstallationID, Policies: f, Recovery: f, Processing: f, Now: func() time.Time { return f.now }}, base.record, scope.Principal
}

func TestCurrentProjectionEnvironmentRequiresIndependentApprovedPolicy(t *testing.T) {
	f, s, r, a := newQueryEnvironmentFixture()
	out, e := s.ProjectionEnvironment(context.Background(), r, a)
	if e != nil || !out.Valid(f.now) || out.Path != f.policy.Path || f.count["policy"] != 2 || f.count["recovery"] != 2 || f.count["processing"] != 2 {
		t.Fatal("independent query environment failed", e)
	}
	for _, name := range []string{"missing-policy", "missing-processing", "missing-recovery", "client", "purpose", "data-class", "source", "native-limit", "download-path", "suspended", "region", "changed-policy", "changed-path", "changed-processing", "changed-recovery"} {
		t.Run(name, func(t *testing.T) {
			f, s, r, a := newQueryEnvironmentFixture()
			switch name {
			case "missing-policy":
				s.Policies = nil
			case "missing-processing":
				s.Processing = nil
			case "missing-recovery":
				s.Recovery = nil
			case "client":
				a.ClientID = "other"
			case "purpose":
				r.PurposeRef = "other"
			case "data-class":
				r.DataClass = "raw"
			case "source":
				r.SourceProjectionDigest = artifact.Digest{3}
			case "native-limit":
				r.Retained.Registration.NativeLimit++
			case "download-path":
				f.policy.Path.Purpose = "download"
			case "suspended":
				f.policy.Suspended = true
			case "region":
				f.policy.PermittedRegions = []string{"elsewhere"}
			default:
				f.on = func(_ context.Context, stage string, n int) {
					if n != 2 {
						return
					}
					switch name {
					case "changed-policy":
						if stage == "policy" {
							f.policy.Revision.Generation++
						}
					case "changed-path":
						if stage == "policy" {
							f.policy.Path.WorkerConfiguration.Generation++
						}
					case "changed-processing":
						if stage == "processing" {
							f.processing.Sequence++
						}
					case "changed-recovery":
						if stage == "recovery" {
							f.recovery.Revision.Generation++
						}
					}
				}
			}
			if _, e := s.ProjectionEnvironment(context.Background(), r, a); e == nil {
				t.Fatal("missing or changed independent query source accepted")
			}
		})
	}
}

func TestCurrentProjectionEnvironmentPreservesEveryOriginalEarlierDeadline(t *testing.T) {
	for _, stage := range []string{"policy", "recovery", "processing"} {
		t.Run(stage, func(t *testing.T) {
			f, s, r, a := newQueryEnvironmentFixture()
			short := f.now.Add(100 * time.Millisecond)
			switch stage {
			case "policy":
				f.policy.FreshUntil = short
			case "recovery":
				f.recovery.FreshUntil = short
			case "processing":
				f.processing.ValidUntil = short
			}
			f.on = func(ctx context.Context, name string, n int) {
				if name == stage && n == 2 {
					f.now = short
					switch stage {
					case "policy":
						f.policy.ObservedAt = short
						f.policy.FreshUntil = short.Add(5 * time.Second)
					case "recovery":
						f.recovery.ObservedAt = short
						f.recovery.FreshUntil = short.Add(5 * time.Second)
					case "processing":
						f.processing.ObservedAt = short
						f.processing.ValidUntil = short.Add(5 * time.Second)
					}
				}
				if n == 2 {
					if d, ok := ctx.Deadline(); !ok || d.After(short) {
						t.Fatal("later read lost original earlier deadline")
					}
				}
			}
			if _, e := s.ProjectionEnvironment(context.Background(), r, a); e == nil {
				t.Fatal("late fresh observation renewed expired original source")
			}
		})
	}
}

func TestCurrentProjectionEnvironmentNarrowsAfterFinalPolicyRead(t *testing.T) {
	f, s, r, a := newQueryEnvironmentFixture()
	short := f.now.Add(time.Second)
	f.on = func(ctx context.Context, name string, n int) {
		if name == "policy" && n == 2 {
			f.policy.FreshUntil = short
		}
		if (name == "recovery" || name == "processing") && n == 2 {
			if d, ok := ctx.Deadline(); !ok || d.After(short) {
				t.Fatal("final source tightening lost before blocking read")
			}
		}
	}
	out, e := s.ProjectionEnvironment(context.Background(), r, a)
	if e != nil || out.ValidUntil.After(short) {
		t.Fatal("tightened policy cutoff not retained", e)
	}
}

func TestCurrentProjectionEnvironmentOwnsOriginalPolicySlices(t *testing.T) {
	f, s, r, a := newQueryEnvironmentFixture()
	f.on = func(_ context.Context, stage string, n int) {
		if stage == "processing" && n == 1 {
			// Reusing a reader's buffer must not rewrite the first accepted
			// snapshot. The actor remains allowed, so only exact body comparison
			// detects this changed source under its unchanged claimed revision.
			f.policy.Clients[0].Purposes = append(f.policy.Clients[0].Purposes, "other-purpose")
		}
	}
	if _, err := s.ProjectionEnvironment(context.Background(), r, a); err == nil {
		t.Fatal("reused policy slice rewrote original source")
	}
}
