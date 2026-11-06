package execution

import (
	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/planning"
	"context"
	"testing"
	"time"
)

type logsRunnerFixture struct {
	*apiRunnerFixture
	starts       int
	startContext context.Context
}

func (f *logsRunnerFixture) PrepareContext(context.Context, artifact.ContextExpectation) (evidence.PreparedContext, error) {
	f.prepares.Add(1)
	return f, nil
}
func (f *logsRunnerFixture) StoreContext(context.Context, []byte, time.Time, time.Time) (artifact.Copies, error) {
	f.stores.Add(1)
	return artifact.Copies{}, value.ErrUnavailable
}
func (f *logsRunnerFixture) Close() { f.closes.Add(1) }
func (f *logsRunnerFixture) StartLogs(ctx context.Context, pin artifact.PinnedPod, started, until time.Time) (time.Time, error) {
	f.starts++
	f.startContext = ctx
	deadline, bounded := ctx.Deadline()
	if !bounded || deadline.After(f.now.Add(5*time.Second)) || ctx.Err() != nil || pin != f.work.Accepted.Pin || !started.Equal(f.record.StartedAt) || until.After(deadline) {
		return time.Time{}, value.ErrDenied
	}
	return started, nil
}
func logsExecutionFixture(t *testing.T) (*logsRunnerFixture, APIContextRunner, identities.CurrentIdentity) {
	t.Helper()
	base, runner, current := apiRunner(t)
	f := &logsRunnerFixture{apiRunnerFixture: base}
	f.retention.EvidenceType = "logs"
	c := planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "logs", Profile: planning.ProfileRef{Catalog: "builtin", Name: "finite-logs", Version: "v1"}}}, MaxTotalBytes: 10 << 20, MaxDuration: "10s"}
	plan, err := compiler.CompileContext(planning.ContextInput{CaptureID: f.work.Accepted.CaptureID, Executor: f.work.Actor, Deadline: f.work.Accepted.Deadline, Target: f.target, Retention: f.retention, Capability: f.cap, Logs: &planning.LogsContext{Composition: c}}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	logs, action, err := compiler.LogsForContext(plan)
	if err != nil {
		t.Fatal(err)
	}
	e := &f.work.Accepted.Expectation
	e.Logs, e.NativeType, e.DataClass, e.ActionID = &logs, artifact.LogsArtifact, "raw", action
	e.PlanDigest, e.RecipeDigest = plan.ScopeDigest, plan.RecipeDigest
	e.Registration.NativeLimit = logs.MaxNativeBytes
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	f.work.Accepted.ScopeDigest = plan.ScopeDigest
	f.resolved.Start.Binding.ActionID = action
	f.resolved.Start.Binding.NativeType = artifact.LogsArtifact
	f.resolved.Start.Binding.NativeBytes = logs.MaxNativeBytes
	runner.Output = f
	return f, runner, current
}
func TestLogsRunnerUsesOrdinaryAPIPreparationAndOneOwnedEffect(t *testing.T) {
	f, runner, current := logsExecutionFixture(t)
	out, err := runner.Execute(t.Context(), current, f.work.Accepted.CaptureID)
	if err != nil || out.State != "Recording" || f.starts != 1 || f.prepares.Load() != 1 || f.record.Phase != "started" || f.stores.Load() != 0 || f.captures.Load() != 0 {
		t.Fatal("logs left exact API start path", out, err, f.starts, f.record.Phase)
	}
	if f.startContext.Err() == nil {
		t.Fatal("start retained original exchange")
	}
	out, err = runner.Execute(t.Context(), current, f.work.Accepted.CaptureID)
	if err != nil || out.State != "AlreadyStarted" || f.starts != 1 || f.prepares.Load() != 1 || f.closes.Load() != 1 {
		t.Fatal("replay acquired new keys/logs", out, err)
	}
}
func TestLogsRunnerRefusesChangedAcceptedTimeoutBeforePreparation(t *testing.T) {
	f, runner, current := logsExecutionFixture(t)
	f.work.Accepted.Expectation.Logs.TimeoutMillis--
	if _, err := runner.Execute(t.Context(), current, f.work.Accepted.CaptureID); err == nil || f.starts != 0 || f.prepares.Load() != 0 {
		t.Fatal("accepted timeout changed before logs start", err)
	}
}
