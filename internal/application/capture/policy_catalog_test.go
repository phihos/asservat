package capture

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/capture"
	planning "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type catalogPolicyObserver struct {
	RestartObserver
	calls  int
	change func(*targets.RestartObservation)
}

func (o *catalogPolicyObserver) ObserveWorkloadRestarts(ctx context.Context, r targets.RestartRequest) (targets.RestartObservation, error) {
	o.calls++
	observed, err := o.RestartObserver.ObserveWorkloadRestarts(ctx, r)
	if o.change != nil {
		o.change(&observed)
	}
	return observed, err
}

func TestPolicyCatalogActivationReusesObservationAndAuthorizesBeforeCompilation(t *testing.T) {
	for _, mode := range []string{"exact", "denied", "expired-during-read", "wrong-observed-workload"} {
		t.Run(mode, func(t *testing.T) {
			f, s := newWorkloadActivationFixture(t)
			observer := &catalogPolicyObserver{RestartObserver: f}
			s.Observer = observer
			reads := 0
			original := s.CompileRecorder
			if mode == "denied" {
				f.projection.DeniesComplete = false
			}
			if mode == "wrong-observed-workload" {
				observer.change = func(o *targets.RestartObservation) { o.Workload.Name = "other" }
			}
			s.CompileRecorder = func(ctx context.Context, scope targets.Request, raw json.RawMessage) ([]planning.PolicyRecorderConfiguration, error) {
				reads++
				if scope.ClusterID != activationCluster || scope.Namespace.UID != "ns-uid" || scope.Workload.UID != "workload-uid" || scope.PodUID != "" {
					t.Fatal("catalog scope invented or lost workload", scope)
				}
				deadline, ok := ctx.Deadline()
				if !ok || deadline.After(f.now.Add(5*time.Second)) {
					t.Fatal("catalog read renewed source/permission observation")
				}
				result, err := original(ctx, scope, raw)
				if mode == "expired-during-read" {
					f.now = deadline.Add(time.Microsecond)
				}
				return result, err
			}
			_, err := s.Activate(t.Context(), f, "restarts", "catalog-first", true)
			if observer.calls != 1 {
				t.Fatal("workload observed more than once", observer.calls)
			}
			if mode == "exact" {
				if err != nil || reads != 1 || len(f.accepted) != 1 {
					t.Fatal("authorized compilation", err, reads, len(f.accepted))
				}
				return
			}
			if err == nil || len(f.accepted) != 0 {
				t.Fatal("refused lookup accepted policy", mode, err)
			}
			if (mode == "denied" || mode == "wrong-observed-workload") && reads != 0 {
				t.Fatal("catalog read before current workload authorization")
			}
		})
	}
}

func TestPolicyCatalogGrantUsesOriginalAcceptedScopeAndDeadline(t *testing.T) {
	for _, expire := range []bool{false, true} {
		f, accepted, s := newPolicyGrantPlanFixture(t)
		original := s.CompileRecorder
		calls := 0
		s.CompileRecorder = func(ctx context.Context, scope targets.Request, raw json.RawMessage) ([]planning.PolicyRecorderConfiguration, error) {
			calls++
			a := accepted.snapshot.Authority
			if scope.ClusterID != a.ClusterID || scope.Namespace.UID != a.NamespaceUID || scope.Workload.UID != a.WorkloadUID || scope.PodUID != "" {
				t.Fatal("grant catalog scope lost accepted UIDs")
			}
			end, ok := ctx.Deadline()
			if !ok || end.After(accepted.snapshot.FreshUntil) {
				t.Fatal("accepted read deadline renewed")
			}
			out, err := original(ctx, scope, raw)
			if expire {
				f.now = end.Add(time.Microsecond)
			}
			return out, err
		}
		_, err := s.PolicyGrantPlan(t.Context(), "policy-uid", "restarts")
		if calls != 1 || (expire && err == nil) || (!expire && err != nil) {
			t.Fatal("grant catalog freshness", expire, calls, err)
		}
	}
}

func TestPolicyCatalogTriggerRetainsOneObservationAndRefusesReplacement(t *testing.T) {
	for _, replace := range []bool{false, true} {
		f, accepted, plans := newPolicyGrantPlanFixture(t)
		observer := &catalogPolicyObserver{RestartObserver: f}
		if replace {
			observer.change = func(o *targets.RestartObservation) { o.Workload.UID = "replacement" }
		}
		ledger := &teamTriggerLedger{}
		inv := newInvestigationFixture()
		trigger := PolicyTrigger{RootID: activationRoot, InstallationID: activationInstallation, RecipeName: "builtin-pod-status-v1", RecipeDigest: testRecipe, CompileRecorder: plans.CompileRecorder, Ledger: ledger, Documents: f, Sources: f, Accepted: triggerAcceptedRecord{accepted}, Observer: observer, Capture: ContextSubmission{ContextInvestigation: inv.svc, Intents: teamNeverStart{t}, Start: teamNeverStart{t}}, Audit: f, Now: func() time.Time { return f.now }}
		original := trigger.CompileRecorder
		trigger.CompileRecorder = func(ctx context.Context, scope targets.Request, raw json.RawMessage) ([]planning.PolicyRecorderConfiguration, error) {
			if scope.Workload.UID != accepted.record.Authority.WorkloadUID || scope.Namespace.UID != accepted.record.Authority.NamespaceUID {
				t.Fatal("trigger replaced accepted scope")
			}
			return original(ctx, scope, raw)
		}
		err := trigger.Tick(t.Context(), value.ActivePolicy{PolicyUID: "policy-uid", Name: "restarts"})
		if observer.calls != 1 {
			t.Fatal("trigger duplicated workload observation", observer.calls)
		}
		if replace {
			if err == nil || len(ledger.ticks) != 0 {
				t.Fatal("replacement reached occurrence ledger")
			}
		} else if err != nil || len(ledger.ticks) != 1 {
			t.Fatal("accepted trigger failed", err)
		}
	}
}
