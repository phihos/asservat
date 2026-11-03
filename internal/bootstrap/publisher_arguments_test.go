package bootstrap

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/objectstore/manifest"
	"asservat.local/asservat/internal/adapters/syscalls"
	planner "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
)

type publisherArgumentSourceFunc func(context.Context, artifact.ContextExpectation) (artifact.ArgumentSourceProvenance, error)

func (f publisherArgumentSourceFunc) AcceptedArgumentSource(ctx context.Context, e artifact.ContextExpectation) (artifact.ArgumentSourceProvenance, error) {
	return f(ctx, e)
}

func publisherArgumentFixture(t *testing.T) (artifact.ContextExpectation, artifact.ArgumentSourceProvenance, artifact.ArgumentHeader, artifact.ArgumentFooter) {
	t.Helper()
	in, now := publicArgumentPlanInput(t, []string{"write"})
	plan, err := planner.CompileRecorder(in, newPublicRecorderCompiler(), now)
	if err != nil {
		t.Fatal(err)
	}
	recording, action, err := planner.RecordingFor(plan)
	if err != nil {
		t.Fatal(err)
	}
	digest := artifact.Digest{1}
	anchor := now.Add(-time.Minute)
	e := artifact.ContextExpectation{ExecutionClass: artifact.ContextAPIExecution, NativeType: artifact.SyscallArgumentsArtifact, Recording: &recording, CaptureUID: runtimeID, PodUID: runtimeID, Namespace: "synthetic", NamespaceUID: runtimeID, WorkloadUID: runtimeID, ActionID: action, CaseID: runtimeID, OccurrenceID: runtimeID, CollectorVersion: "synthetic", CollectorImageDigest: digest, RecipeDigest: plan.RecipeDigest, PlanDigest: plan.ScopeDigest, DataClass: "raw", PurposeRef: "diagnostics", TriggeredAt: anchor,
		Registration: artifact.Registration{Location: artifact.Location{ClusterID: runtimeID, ArtifactID: runtimeID, AttemptID: runtimeID}, StoreID: runtimeID, AllocationID: runtimeID, PoolRevision: 1, AllocationRevision: 1, NativeLimit: artifact.RecordingNativeLimit, AnchorAt: anchor, WriteUntil: now.Add(time.Minute), ExpiresAt: anchor.Add(180 * time.Second), DeleteBy: anchor.Add(240 * time.Second)},
		Audience:     []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://identity.synthetic.invalid", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: runtimeID, BasisDigest: digest}}, RequestedAgeSeconds: 180, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 60, RetentionRules: []artifact.RetentionRule{{UID: "retention", Generation: 1, Digest: digest}}}
	if err = e.Validate(); err != nil {
		t.Fatal("accepted argument expectation", err)
	}
	// The source is independent of the native bytes and remains historical:
	// its original observation session is not another collection lease.
	source := artifact.ArgumentSourceProvenance{PodUID: e.PodUID, NodeUID: runtimeID, BootID: runtimeID, CollectorPodUID: runtimeID, CollectorEpoch: runtimeID, SessionID: runtimeID, Fence: runtimeID, StartedAt: now.Add(-time.Minute), StartBy: now.Add(-59 * time.Second), Until: now.Add(-57 * time.Second)}
	a := recording.Arguments
	h := artifact.ArgumentHeader{Record: "header", Format: syscalls.ArgumentNativeFormat, PodUID: e.PodUID, NodeUID: source.NodeUID, BootID: source.BootID, CollectorPodUID: source.CollectorPodUID, SourceEpoch: source.CollectorEpoch, SessionID: source.SessionID, Fence: source.Fence, EngineDigest: hex.EncodeToString(a.ProgramDigest[:]), DefinitionDigest: hex.EncodeToString(a.DefinitionDigest[:]), AccountingRule: hex.EncodeToString(a.AccountingRule[:]), Decoder: syscalls.ArgumentDecoderVersion, ABI: syscalls.ABI, StartedAt: source.StartedAt}
	f := artifact.ArgumentFooter{Record: "footer", EndedAt: source.Until, Outcome: "completed", CoverageUnknown: true}
	return e, source, h, f
}

func writePublisherArgument(t *testing.T, check objectstore.StreamCheck, lines ...any) error {
	t.Helper()
	for _, line := range lines {
		raw, err := syscalls.AppendArgumentLine(nil, line)
		if err != nil {
			t.Fatal(err)
		}
		for len(raw) > 0 {
			n := min(7, len(raw))
			if err = check.Write(raw[:n]); err != nil {
				return err
			}
			raw = raw[n:]
		}
	}
	return check.Close()
}

func TestPublisherArgumentCheckRequiresIndependentOriginalSource(t *testing.T) {
	for _, field := range []string{"original", "fence", "node", "epoch", "boot", "collector", "session"} {
		t.Run(field, func(t *testing.T) {
			e, source, header, footer := publisherArgumentFixture(t)
			const other = "22222222-2222-4222-8222-222222222222"
			switch field {
			case "fence":
				header.Fence = other
			case "node":
				header.NodeUID = other
			case "epoch":
				header.SourceEpoch = other
			case "boot":
				header.BootID = other
			case "collector":
				header.CollectorPodUID = other
			case "session":
				header.SessionID = other
			}
			v, err := manifest.New()
			if err != nil {
				t.Fatal(err)
			}
			structural, err := v.NativeCheck(e, manifest.ContextManifest{StartedAt: header.StartedAt, CompletedAt: footer.EndedAt})
			if err != nil {
				t.Fatal(err)
			}
			if err = writePublisherArgument(t, structural, header, footer); err != nil {
				t.Fatal("fixture must remain structurally valid", err)
			}
			calls := 0
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(750*time.Millisecond))
			defer cancel()
			check, err := publisherArgumentCheck(ctx, publisherArgumentSourceFunc(func(actual context.Context, expected artifact.ContextExpectation) (artifact.ArgumentSourceProvenance, error) {
				calls++
				deadline, _ := ctx.Deadline()
				got, bounded := actual.Deadline()
				if actual != ctx || !bounded || !got.Equal(deadline) || !reflect.DeepEqual(expected, e) {
					t.Fatal("source lookup changed caller context, deadline or expectation")
				}
				return source, nil
			}), e)
			if err != nil || calls != 1 {
				t.Fatal("independent source resolution", err, calls)
			}
			err = writePublisherArgument(t, check, header, footer)
			if (err == nil) != (field == "original") {
				t.Fatal("source provenance verdict", field, err)
			}
		})
	}
}

func TestPublisherArgumentCheckRefusesMissingFailedAndCancelledSource(t *testing.T) {
	for _, mode := range []string{"missing reader", "missing source", "failed read", "cancelled before", "cancelled during"} {
		t.Run(mode, func(t *testing.T) {
			e, source, _, _ := publisherArgumentFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			failure := errors.New("source unavailable")
			var reader argumentSourceReader = publisherArgumentSourceFunc(func(actual context.Context, _ artifact.ContextExpectation) (artifact.ArgumentSourceProvenance, error) {
				calls++
				if actual != ctx {
					t.Fatal("source lost original cancellation")
				}
				switch mode {
				case "missing source":
					return artifact.ArgumentSourceProvenance{}, nil
				case "failed read":
					return source, failure
				case "cancelled during":
					cancel()
				}
				return source, nil
			})
			if mode == "missing reader" {
				reader = nil
			}
			if mode == "cancelled before" {
				cancel()
			}
			_, err := publisherArgumentCheck(ctx, reader, e)
			if err == nil {
				t.Fatal("unavailable source produced a semantic checker", err)
			}
			if (mode == "missing reader" || mode == "cancelled before") && calls != 0 {
				t.Fatal("cancelled/missing lookup was attempted")
			}
			if mode == "failed read" && !errors.Is(err, failure) {
				t.Fatal("source failure lost", err)
			}
			if (mode == "cancelled before" || mode == "cancelled during") && !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled source read accepted", err)
			}
		})
	}
}
