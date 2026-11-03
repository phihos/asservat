package execution

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type argumentRunnerFixture struct {
	*apiRunnerFixture
	compiler.FilterCompiler
	source                        targets.PacketSourceObservation
	permit                        collector.ArgumentObservationPermit
	catalog                       []planning.CatalogProfile
	resolutionErr, preparationErr error
	prepareCalls, starts          int
	startContext                  context.Context
	startUntil                    time.Time
}

func (f *argumentRunnerFixture) CompileArguments(_ []string, buffers bool, maximum int64) (artifact.RecordingArguments, error) {
	return artifact.RecordingArguments{ProgramDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AccountingRule: artifact.Digest(collector.ArgumentObservationAccountingRule()), MaxProbeBytes: 256, MaxBytesPerEvent: maximum, MaxBytesPerSecond: planning.SensitiveMaxBytesPerSecond, CaptureBuffers: buffers}, nil
}
func (f *argumentRunnerFixture) ResolveArgumentSource(context.Context, targets.Request) (targets.RecorderResolution, error) {
	return targets.RecorderResolution{Target: f.target, Recorder: targets.RecorderAnswer{Outcome: targets.RecorderAvailable, Source: &f.source}}, f.resolutionErr
}
func (f *argumentRunnerFixture) ReadCatalogProfiles(context.Context, targets.PodResolution, []planning.ProfileRef) ([]planning.CatalogProfile, error) {
	return f.catalog, nil
}
func (f *argumentRunnerFixture) StoreContext(context.Context, []byte, time.Time, time.Time) (artifact.Copies, error) {
	return artifact.Copies{}, value.ErrUnavailable
}
func (f *argumentRunnerFixture) Close() { f.closes.Add(1) }
func (f *argumentRunnerFixture) PrepareArgumentRecording(ctx context.Context, check APIExecutionCheck, source targets.PacketSourceObservation) (value.APIExecution, bool, collector.ArgumentObservationPermit, error) {
	f.prepareCalls++
	if source != f.source || check.ValidUntil.After(source.FreshUntil) {
		return value.APIExecution{}, false, collector.ArgumentObservationPermit{}, value.ErrDenied
	}
	if f.preparationErr != nil {
		return value.APIExecution{}, false, collector.ArgumentObservationPermit{}, f.preparationErr
	}
	r, first, err := f.apiRunnerFixture.PrepareAPIExecution(ctx, check)
	return r, first, f.permit, err
}
func (f *argumentRunnerFixture) PrepareContext(context.Context, artifact.ContextExpectation) (evidence.PreparedContext, error) {
	f.prepares.Add(1)
	return f, nil
}
func (f *argumentRunnerFixture) StartArgumentRecording(ctx context.Context, pin artifact.PinnedPod, started, until time.Time, source targets.PacketSourceObservation, permit collector.ArgumentObservationPermit) (time.Time, error) {
	f.starts++
	f.startContext, f.startUntil = ctx, until
	deadline, bounded := ctx.Deadline()
	if !bounded || deadline.After(f.source.FreshUntil) || until.After(f.source.FreshUntil) || ctx.Err() != nil || pin != f.work.Accepted.Pin || !started.Equal(f.record.StartedAt) || source != f.source || permit != f.permit {
		return time.Time{}, value.ErrDenied
	}
	return started, nil
}

func argumentExecutionFixture(t *testing.T) (*argumentRunnerFixture, APIContextRunner, identities.CurrentIdentity) {
	t.Helper()
	base, runner, current := apiRunner(t)
	f := &argumentRunnerFixture{apiRunnerFixture: base}
	raw, err := os.ReadFile("../planning/profiles/syscall-activity-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["name"] = "arguments"
	a := doc["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)
	a["impact"], a["executionMode"] = "sensitiveRead", "onTrigger"
	p := a["parameters"].(map[string]any)
	p["mode"], p["before"], p["after"] = "arguments", "0s", "3s"
	p["syscalls"] = map[string]any{"mode": "include", "names": []string{"read"}}
	p["arguments"] = map[string]any{"maxBytesPerEvent": 128, "captureBuffers": false}
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	ref := planning.ProfileRef{Catalog: "namespace", Name: "arguments", Version: "v1"}
	c := planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "calls", Profile: ref}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s", Resolved: []planning.CatalogProfile{{Ref: ref, SourceClusterID: f.target.Request.ClusterID, SourceNamespaceUID: f.target.Request.Namespace.UID, SourceUID: "profile-uid", Document: raw, Enabled: true}}}
	f.catalog = c.Resolved
	f.retention.EvidenceType = "syscallTrace"
	compiled, err := compiler.CompileRecorder(planning.RecorderInput{CaptureID: f.work.Accepted.CaptureID, Executor: f.work.Actor, Target: f.target, Composition: c, Retention: f.retention, Deadline: f.work.Accepted.Deadline}, f, f.now)
	if err != nil {
		t.Fatal("compile recorder", err)
	}
	frozen, err := compiler.RecorderContextFromScope(c, compiled.CanonicalScope)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compiler.CompileContext(planning.ContextInput{CaptureID: f.work.Accepted.CaptureID, Executor: f.work.Actor, Deadline: f.work.Accepted.Deadline, Target: f.target, Retention: f.retention, Capability: f.cap, Recorder: frozen}, f.now)
	if err != nil {
		t.Fatal("compile accepted context", err)
	}
	r, action, err := compiler.RecordingForContext(plan)
	if err != nil {
		t.Fatal(err)
	}
	e := &f.work.Accepted.Expectation
	e.Recording, e.ActionID, e.NativeType, e.DataClass = &r, action, artifact.SyscallArgumentsArtifact, "raw"
	e.PlanDigest, e.RecipeDigest = plan.ScopeDigest, plan.RecipeDigest
	e.Registration.NativeLimit = artifact.RecordingNativeLimit
	if err = e.Validate(); err != nil {
		t.Fatal("accepted expectation", err)
	}
	f.work.Accepted.ScopeDigest = plan.ScopeDigest
	f.resolved.Start.Binding.ActionID = action
	f.resolved.Start.Binding.NativeBytes = e.Registration.NativeLimit
	f.source = targets.PacketSourceObservation{PodUID: e.PodUID, NodeUID: "node", BootID: contextID(65), CollectorPodUID: contextID(66), CollectorEpoch: contextID(67), ObservedAt: f.now, FreshUntil: f.now.Add(4 * time.Second)}
	f.resolved.Start.ValidUntil = f.source.FreshUntil
	f.permit = collector.ArgumentObservationPermit{Binding: collector.ArgumentObservationBinding{Scope: [32]byte(e.PlanDigest), ProgramDigest: [32]byte(r.Arguments.ProgramDigest), DefinitionDigest: [32]byte(r.Arguments.DefinitionDigest), ExpectationDigest: [32]byte(evidence.ContextExpectationDigest(*e)), AccountingRule: collector.ArgumentObservationAccountingRule(), SessionID: contextID(70), Fence: contextID(71), CaptureID: e.CaptureUID, ActionID: action, PodUID: e.PodUID, NodeUID: f.source.NodeUID, BootID: f.source.BootID, CollectorPodUID: f.source.CollectorPodUID, CollectorEpoch: f.source.CollectorEpoch}, StartedAt: f.now, StartBy: f.now.Add(4 * time.Second), SessionUntil: f.now.Add(7 * time.Second), LeaseUntil: f.now.Add(7 * time.Second), Duration: 3 * time.Second, Sequence: 1, EventCredit: 1000, ByteCredit: 256000, EventsPerSecond: 100, BytesPerSecond: planning.SensitiveMaxBytesPerSecond, MaxProbeBytes: 256, MaxBytesPerEvent: 128, MaxTrackedThreads: 4096}
	if !f.permit.ValidFinite(f.now) {
		t.Fatal("fixture permit")
	}
	runner.Targets, runner.Prepare, runner.Profiles, runner.Output = f, f, f, f
	return f, runner, current
}

func TestArgumentRunnerUsesExactSourceAndDistinctPermit(t *testing.T) {
	f, runner, current := argumentExecutionFixture(t)
	out, err := runner.Execute(t.Context(), current, f.work.Accepted.CaptureID)
	if err != nil || out.State != "Recording" || f.prepareCalls != 1 || f.starts != 1 || f.record.Phase != "started" {
		t.Fatal("argument dispatch", out, err, f.prepareCalls, f.starts, f.record.Phase)
	}
	if f.startContext.Err() == nil {
		t.Fatal("completed start retained its context")
	}
	out, err = runner.Execute(t.Context(), current, f.work.Accepted.CaptureID)
	if err != nil || out.State != "AlreadyStarted" || f.starts != 1 || f.prepares.Load() != 1 {
		t.Fatal("replay reacquired arguments", out, err)
	}
}

func TestArgumentRunnerRefusesUnavailableSourceAndUncertainPreparation(t *testing.T) {
	for _, mode := range []string{"missing resolver", "wrong pod", "expired", "unavailable", "missing preparer", "unknown preparation"} {
		t.Run(mode, func(t *testing.T) {
			f, runner, current := argumentExecutionFixture(t)
			switch mode {
			case "missing resolver":
				runner.Targets = f.apiRunnerFixture
			case "wrong pod":
				f.source.PodUID = "replacement"
			case "expired":
				f.source.FreshUntil = f.now
			case "unavailable":
				f.resolutionErr = targets.ErrUnavailable
			case "missing preparer":
				runner.Prepare = f.apiRunnerFixture
			case "unknown preparation":
				f.preparationErr = value.ErrUnavailable
			}
			_, err := runner.Execute(t.Context(), current, f.work.Accepted.CaptureID)
			if err == nil || errors.Is(err, value.ErrNotStarted) || f.starts != 0 || f.prepares.Load() != 0 {
				t.Fatal("refusal created keys or dispatched", err, f.starts, f.prepares.Load())
			}
		})
	}
}
