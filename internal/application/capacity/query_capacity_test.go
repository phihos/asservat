package capacity

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type queryDeploymentGuardFunc func(context.Context, ContextQueryQualification, QueryDeploymentPin, func(context.Context) error) error

func (f queryDeploymentGuardFunc) WithCurrentQueryDeployment(c context.Context, q ContextQueryQualification, p QueryDeploymentPin, next func(context.Context) error) error {
	return f(c, q, p, next)
}

type queryCapacityReadFake struct {
	source    QueryCapacitySource
	reads     int
	final     func(*QueryCapacitySource)
	waitFinal bool
	plan      func() (value.ContextQueryPlan, error)
}

func (f *queryCapacityReadFake) ReadQueryCapacitySource(ctx context.Context, _ artifact.RecoveryProof) (QueryCapacitySource, error) {
	f.reads++
	if f.waitFinal && f.reads > 1 {
		<-ctx.Done()
		return QueryCapacitySource{}, ctx.Err()
	}
	s := f.source
	if f.reads > 1 && f.final != nil {
		f.final(&s)
	}
	return s, nil
}
func (f *queryCapacityReadFake) ReadQueryCapacityPlan(context.Context, QueryCapacitySource, value.ContextProjectionAuthority, string) (value.ContextQueryPlan, error) {
	if f.plan != nil {
		return f.plan()
	}
	return value.ContextQueryPlan{}, value.ErrUnavailable
}
func (f *queryCapacityReadFake) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return f.source.Recovery, nil
}

func queryCapacityServiceFixture(t *testing.T) (ProtectedContextQueryCapacity, *queryCapacityReadFake, *time.Time) {
	t.Helper()
	q, pool, _, root := queryCapacityFixture(t)
	n := time.Now().UTC().Truncate(time.Microsecond)
	r := artifact.RecoveryProof{InstallationID: q.RootBacking.InstallationID, IssuerEpoch: q.ID, Revision: identity.Revision{UID: q.ID, Generation: 1, Digest: artifact.Digest{1}}, ObservedAt: n, FreshUntil: n.Add(4 * time.Second)}
	f := &queryCapacityReadFake{source: QueryCapacitySource{Qualification: q, Root: root, System: pool, AcceptanceID: q.ID, Ready: true, BackingUntil: n.Add(time.Second), SetupInputDigest: artifact.Digest{3}, SourceRevision: 1, SourceDigest: artifact.Digest{4}, Recovery: r, ObservedAt: n, FreshUntil: r.FreshUntil}}
	pass := queryDeploymentGuardFunc(func(c context.Context, _ ContextQueryQualification, _ QueryDeploymentPin, next func(context.Context) error) error {
		return next(c)
	})
	s := ProtectedContextQueryCapacity{RootID: root.RootID, InstallationID: r.InstallationID, Store: f, Recovery: f, Deployments: QueryDeploymentGuards{pass, pass, pass, pass}, Now: func() time.Time { return n }, NewID: func() string { return q.ID }}
	if !f.source.Valid(n) {
		t.Fatal("invalid synthetic source")
	}
	return s, f, &n
}

func TestQueryCapacityPolicyKeepsOriginalBackingDeadline(t *testing.T) {
	s, f, now := queryCapacityServiceFixture(t)
	p, err := s.ContextProjectionPolicy(context.Background())
	if err != nil || !p.FreshUntil.Equal(f.source.BackingUntil) {
		t.Fatal("root observation extended query backing", err)
	}
	// A later fresh observation cannot extend the first response's original
	// backing deadline while external guards complete their final checks.
	f.reads = 0
	f.final = func(last *QueryCapacitySource) { last.BackingUntil = last.FreshUntil }
	s.Deployments.Worker = queryDeploymentGuardFunc(func(c context.Context, _ ContextQueryQualification, _ QueryDeploymentPin, next func(context.Context) error) error {
		err := next(c)
		*now = now.Add(2 * time.Second)
		return err
	})
	if _, err = s.ContextProjectionPolicy(context.Background()); err == nil {
		t.Fatal("expired original query backing renewed by later observation")
	}
}

func TestQueryCapacityPolicyRejectsChangesAfterGuards(t *testing.T) {
	for _, mode := range []string{"missing-acceptance", "expired-backing", "negative", "source-revision", "root-attempt", "setup-input", "recovery-epoch"} {
		t.Run(mode, func(t *testing.T) {
			s, f, now := queryCapacityServiceFixture(t)
			switch mode {
			case "missing-acceptance":
				f.source.AcceptanceID = ""
			case "expired-backing":
				f.source.BackingUntil = *now
			default:
				f.final = func(last *QueryCapacitySource) {
					switch mode {
					case "negative":
						last.Ready = false
					case "source-revision":
						last.SourceRevision++
					case "root-attempt":
						last.Root.AttemptID = "30000000-0000-4000-8000-000000000099"
					case "setup-input":
						last.SetupInputDigest[0]++
					case "recovery-epoch":
						last.Recovery.IssuerEpoch = "30000000-0000-4000-8000-000000000099"
					}
				}
			}
			if _, err := s.ContextProjectionPolicy(context.Background()); err == nil {
				t.Fatal("changed/unaccepted query source exposed a policy")
			}
		})
	}
}

func TestQueryCapacityRequiresEveryIndependentDeploymentGuard(t *testing.T) {
	q, _, _, _ := queryCapacityFixture(t)
	var order []string
	pass := queryDeploymentGuardFunc(func(c context.Context, _ ContextQueryQualification, p QueryDeploymentPin, next func(context.Context) error) error {
		order = append(order, p.Role)
		return next(c)
	})
	g := QueryDeploymentGuards{pass, pass, pass, pass}
	called := 0
	if e := g.with(context.Background(), *q.ContextQuery, func(context.Context) error { called++; return nil }); e != nil || called != 1 || len(order) != 4 {
		t.Fatal("complete independent guards failed", e)
	}
	for i := 0; i < 4; i++ {
		v := g
		*[]*QueryDeploymentGuard{&v.Worker, &v.Hub, &v.KeyService, &v.Provider}[i] = nil
		if e := v.with(context.Background(), *q.ContextQuery, func(context.Context) error { t.Fatal("missing deployment guard allowed effect"); return nil }); e == nil {
			t.Fatal("worker proof substituted for another deployment")
		}
	}
}

func TestQueryCapacityGuardCannotOmitRepeatOrDiscardCallbackFailure(t *testing.T) {
	q, _, _, _ := queryCapacityFixture(t)
	pass := queryDeploymentGuardFunc(func(c context.Context, _ ContextQueryQualification, _ QueryDeploymentPin, next func(context.Context) error) error {
		return next(c)
	})
	for _, mode := range []string{"omit", "repeat", "hide-error", "after-effect-error", "late-callback"} {
		t.Run(mode, func(t *testing.T) {
			var retained func(context.Context) error
			bad := queryDeploymentGuardFunc(func(c context.Context, _ ContextQueryQualification, _ QueryDeploymentPin, next func(context.Context) error) error {
				switch mode {
				case "omit":
					return nil
				case "repeat":
					_ = next(c)
					_ = next(c)
					return nil
				case "hide-error":
					_ = next(c)
					return nil
				case "after-effect-error":
					_ = next(c)
					return errors.New("private guard state")
				case "late-callback":
					retained = next
					return nil
				}
				return nil
			})
			var calls atomic.Int32
			e := (QueryDeploymentGuards{bad, pass, pass, pass}).with(context.Background(), *q.ContextQuery, func(context.Context) error {
				calls.Add(1)
				if mode == "hide-error" {
					return value.ErrUnavailable
				}
				return nil
			})
			if e == nil {
				t.Fatal("broken guard reported success")
			}
			if retained != nil && retained(context.Background()) == nil {
				t.Fatal("late callback accepted")
			}
			if calls.Load() > 1 {
				t.Fatal("effect repeated")
			}
		})
	}
}

func TestQueryCapacityGuardPreservesParentCancellationAndEarlierChildDeadline(t *testing.T) {
	q, _, _, _ := queryCapacityFixture(t)
	for _, mode := range []string{"parent-cancel", "earlier-child", "late-return"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			short := time.Now().Add(30 * time.Millisecond)
			bad := queryDeploymentGuardFunc(func(_ context.Context, _ ContextQueryQualification, _ QueryDeploymentPin, next func(context.Context) error) error {
				child, stop := context.WithDeadline(context.Background(), short)
				defer stop()
				if mode == "parent-cancel" {
					cancel()
				}
				e := next(child)
				if mode == "late-return" {
					<-child.Done()
					return nil
				}
				return e
			})
			pass := queryDeploymentGuardFunc(func(c context.Context, _ ContextQueryQualification, _ QueryDeploymentPin, next func(context.Context) error) error {
				return next(c)
			})
			e := (QueryDeploymentGuards{bad, pass, pass, pass}).with(ctx, *q.ContextQuery, func(c context.Context) error {
				if mode == "parent-cancel" {
					t.Fatal("replacement context lost parent cancellation")
				}
				if d, ok := c.Deadline(); !ok || d.After(short) {
					t.Fatal("earlier guard bound discarded")
				}
				if mode == "earlier-child" {
					<-c.Done()
					return nil
				}
				return nil
			})
			if e == nil {
				t.Fatal("expired/canceled original guard succeeded")
			}
		})
	}
}

func TestQueryCapacityConsumerBoundsBlockingGuardsAndFinalSource(t *testing.T) {
	for _, mode := range []string{"guard", "final-source"} {
		t.Run(mode, func(t *testing.T) {
			s, f, _ := queryCapacityServiceFixture(t)
			f.source.BackingUntil = time.Now().Add(30 * time.Millisecond)
			if mode == "guard" {
				s.Deployments.Worker = queryDeploymentGuardFunc(func(c context.Context, _ ContextQueryQualification, _ QueryDeploymentPin, _ func(context.Context) error) error {
					<-c.Done()
					return c.Err()
				})
			} else {
				f.waitFinal = true
			}
			outer, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			start := time.Now()
			if _, err := s.ContextProjectionPolicy(outer); err == nil {
				t.Fatal("blocked operation returned current policy")
			}
			if time.Since(start) > 300*time.Millisecond {
				t.Fatal("blocking port outlived original query backing")
			}
		})
	}
}
