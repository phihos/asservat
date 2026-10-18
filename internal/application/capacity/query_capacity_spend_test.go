package capacity

import (
	"context"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
)

type queryCapacitySpendFake struct {
	starts, accepts, completes int
	deny                       bool
	source                     *QueryCapacitySource
	complete                   func(context.Context) error
}

func (f *queryCapacitySpendFake) BeginQueryCapacityObservation(_ context.Context, source QueryCapacitySource, plan QueryBackingPlan, id string) (QueryCapacityObservation, error) {
	f.starts++
	if f.deny {
		return QueryCapacityObservation{}, value.ErrUnavailable
	}
	if f.source != nil {
		f.source.ObservationCount = source.ObservationCount + 1
	}
	return QueryCapacityObservation{ID: id, AcceptanceID: plan.AcceptanceID, Ordinal: source.ObservationCount + 1, ObservedAt: source.ObservedAt, ValidUntil: source.FreshUntil}, nil
}
func (f *queryCapacitySpendFake) AcceptQueryCapacity(_ context.Context, _ QueryCapacitySource, plan QueryBackingPlan, _ QueryCapacityObservation) (QueryBackingPlan, error) {
	f.accepts++
	return plan, nil
}
func (f *queryCapacitySpendFake) AllocateQueryCapacity(context.Context, QueryBackingPlan, WorkloadCapacityKey, string) (string, error) {
	return "", value.ErrUnavailable
}
func (f *queryCapacitySpendFake) SuspendQueryCapacity(context.Context, time.Time) error { return nil }
func (f *queryCapacitySpendFake) CompleteQueryCapacityObservation(ctx context.Context, _ QueryCapacityObservation) error {
	f.completes++
	if f.complete != nil {
		return f.complete(ctx)
	}
	return nil
}

func TestQueryCapacityProducerSpendsBeforeGuardAndDeniesUnknownStart(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(map[bool]string{false: "guard-failure", true: "unknown-start"}[denied], func(t *testing.T) {
			s, _, _ := queryCapacityServiceFixture(t)
			writer := &queryCapacitySpendFake{deny: denied}
			guards := 0
			s.Deployments.Worker = queryDeploymentGuardFunc(func(context.Context, ContextQueryQualification, QueryDeploymentPin, func(context.Context) error) error {
				guards++
				if writer.starts != 1 || denied {
					t.Error("native guard entered without acknowledged paid attempt")
				}
				return value.ErrUnavailable
			})
			if (ProtectedContextQueryProducer{Current: s, Writer: writer}).Reconcile(context.Background(), nil) == nil {
				t.Fatal("failed work accepted")
			}
			want := 1
			if denied {
				want = 0
			}
			if writer.starts != 1 || guards != want || writer.accepts != 0 {
				t.Fatalf("starts=%d guards=%d accepts=%d", writer.starts, guards, writer.accepts)
			}
		})
	}
}

func TestQueryCapacityProducerExhaustionPrecedesEveryGuard(t *testing.T) {
	s, f, _ := queryCapacityServiceFixture(t)
	f.source.ObservationCount = f.source.Qualification.ContextQuery.SourceTransitionLimit
	writer := &queryCapacitySpendFake{}
	s.Deployments.Worker = queryDeploymentGuardFunc(func(context.Context, ContextQueryQualification, QueryDeploymentPin, func(context.Context) error) error {
		t.Fatal("exhausted source entered native work")
		return nil
	})
	if (ProtectedContextQueryProducer{Current: s, Writer: writer}).Reconcile(context.Background(), nil) == nil || writer.starts != 0 || writer.completes != 0 {
		t.Fatal("exhausted original allowance reused")
	}
}

func TestQueryCapacityProducerCompletesOnlyJoinedWork(t *testing.T) {
	for _, mode := range []string{"success", "guard-failure", "cancelled-caller", "expired-original"} {
		t.Run(mode, func(t *testing.T) {
			s, f, now := queryCapacityServiceFixture(t)
			writer := &queryCapacitySpendFake{source: &f.source}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			joined := false
			writer.complete = func(cleanup context.Context) error {
				if !joined || cleanup.Err() != nil {
					t.Fatal("completion ran before join or inherited cancelled request")
				}
				d, ok := cleanup.Deadline()
				if !ok || !d.Equal(f.source.FreshUntil) {
					t.Fatal("completion renewed original cutoff")
				}
				return nil
			}
			s.Deployments.Worker = queryDeploymentGuardFunc(func(c context.Context, _ ContextQueryQualification, _ QueryDeploymentPin, next func(context.Context) error) error {
				err := next(c)
				if writer.completes != 0 {
					t.Fatal("SQL acceptance released live outer guard")
				}
				joined = true
				switch mode {
				case "guard-failure":
					return value.ErrUnavailable
				case "cancelled-caller":
					cancel()
					return context.Canceled
				case "expired-original":
					*now = f.source.FreshUntil.Add(time.Millisecond)
					return context.DeadlineExceeded
				}
				return err
			})
			err := (ProtectedContextQueryProducer{Current: s, Writer: writer}).Reconcile(ctx, nil)
			if (err == nil) != (mode == "success") || writer.starts != 1 || writer.accepts != 1 {
				t.Fatalf("mode %s error=%v starts=%d accepts=%d", mode, err, writer.starts, writer.accepts)
			}
			want := 1
			if mode == "expired-original" {
				want = 0
			}
			if writer.completes != want {
				t.Fatalf("completions=%d want=%d", writer.completes, want)
			}
		})
	}
}
