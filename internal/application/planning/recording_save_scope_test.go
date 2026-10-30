package planning

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

func recordingSaveScopeInput(t *testing.T) (RecordingSaveScopeInput, time.Time) {
	t.Helper()
	snapshot, now := sourceSnapshotInput(t)
	installation := "00000000-0000-4000-8000-000000000098"
	a := authorization.AcceptedPolicyAuthority{InstallationID: installation, PolicyUID: "policy", Creator: snapshot.Executor, Executor: authorization.PolicyPrincipal(installation, "policy"), ScopeDigest: artifact.Digest{7}, ClusterID: snapshot.Target.Request.ClusterID, NamespaceUID: snapshot.Target.Request.Namespace.UID, WorkloadUID: snapshot.Target.Request.Workload.UID, Delegation: identity.Revision{UID: "binding", Generation: 1, Digest: artifact.Digest{1}}, Owners: snapshot.Snapshot.SourceAudience, Actions: []string{"packetCapture"}, Limits: authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 64 << 20, MaxObservedBytes: 1 << 30}, IssuedAt: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	if !a.Valid(now) {
		t.Fatal("accepted policy fixture")
	}
	original := targets.SourceSnapshotTarget{Request: snapshot.Target.Request, Pin: snapshot.Target.Pin, NodeUID: "00000000-0000-4000-8000-000000000070", BootID: "00000000-0000-4000-8000-000000000071", CollectorPodUID: "00000000-0000-4000-8000-000000000072", CollectorEpoch: "00000000-0000-4000-8000-000000000073", SourceID: snapshot.Snapshot.Request.SourceID, Fence: snapshot.Snapshot.Request.Fence, BindingDigest: [32]byte(snapshot.Snapshot.Request.SourceBindingDigest)}
	return RecordingSaveScopeInput{CaptureID: snapshot.CaptureID, Requester: snapshot.Executor, Authority: a, Sources: []RecordingSaveScopeSource{{PolicyUID: a.PolicyUID, ExecutionDigest: a.ScopeDigest, Original: original, ActionID: "traffic", Kind: "packetCapture", DefinitionDigest: artifact.Digest{3}, AudienceDigest: snapshot.Snapshot.SourceAudienceDigest, ApprovedBefore: 30 * time.Second, Before: 20 * time.Second, MaxBytes: 4 << 20}}, IncidentPodLimit: 1, FinalizeTimeout: 20 * time.Second, CeilingDigest: artifact.Digest{4}, RetentionDigest: artifact.Digest{5}}, now
}

func TestRecordingSaveScopeBindsRequesterAndOriginalExecutorWithAfterZero(t *testing.T) {
	in, now := recordingSaveScopeInput(t)
	raw, digest, err := CompileRecordingSaveScope(in, now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ReadContextScopeIdentity(raw, digest)
	if err != nil || parsed.Actor != in.Authority.Executor || parsed.Requester == nil || *parsed.Requester != in.Requester || parsed.Actor == in.Requester {
		t.Fatal("manual initiator replaced original policy executor", parsed, err)
	}
	var scope map[string]json.RawMessage
	if json.Unmarshal(raw, &scope) != nil || string(scope["schemaVersion"]) != `"recording-save/v1"` || string(scope["operation"]) != `"recordingSave"` {
		t.Fatal("wrong protected operation shape")
	}
	var sources []map[string]json.RawMessage
	if json.Unmarshal(scope["sources"], &sources) != nil || len(sources) != 1 || string(sources[0]["after"]) != `"0s"` {
		t.Fatal("manual save acquired a post-window")
	}
	changed := in
	changed.Requester.Subject = "another-current-maintainer"
	other, otherDigest, err := CompileRecordingSaveScope(changed, now)
	if err != nil || digest == otherDigest || bytes.Equal(raw, other) {
		t.Fatal("requester absent from immutable save scope", err)
	}
	// Admission clocks, handles, grants, sharing and the rest of the policy
	// recipe are absent from the closed scope, so none can be replay settings.
	for _, key := range []string{"t0", "recording_handles", "grant", "sharing", "profileComposition"} {
		if _, ok := scope[key]; ok {
			t.Fatal("transient or broader recipe input retained", key)
		}
	}
}

func TestRecordingSaveContextUsesTypedManualScopeAndSeparateAcceptanceClock(t *testing.T) {
	scope, now := recordingSaveScopeInput(t)
	in, _ := sourceSnapshotInput(t)
	source := &scope.Sources[0]
	source.ActionID, source.Before, source.MaxBytes = in.Snapshot.ActionID, in.Snapshot.Request.Before, in.Snapshot.Request.MaxBytes
	in.Snapshot.SourceDefinitionDigest = source.DefinitionDigest
	scope.CeilingDigest = artifact.Digest(in.Capability.Revision.Digest)
	scope.RetentionDigest = artifact.Digest(in.Retention.PolicyRevision.Digest)
	raw, digest, err := CompileRecordingSaveScope(scope, now)
	if err != nil {
		t.Fatal(err)
	}
	in.Executor = scope.Authority.Executor
	in.Snapshot.SourceTarget = &source.Original
	in.Snapshot.TriggerKind = "recordingSave"
	in.Snapshot.RecordingSaveScope = raw
	plan, err := CompileContext(in, now)
	if err != nil || plan.ScopeDigest != digest || !bytes.Equal(plan.CanonicalScope, raw) {
		t.Fatal("typed existing-source manual scope was replaced", err)
	}
	parsed, err := ReadContextScopeIdentity(plan.CanonicalScope, plan.ScopeDigest)
	if err != nil || parsed.Requester == nil || *parsed.Requester != scope.Requester || parsed.Actor != scope.Authority.Executor {
		t.Fatal("dual principal lost", err)
	}
	later := in
	later.Snapshot = in.Snapshot.Clone()
	later.Snapshot.Request.T0 = later.Snapshot.Request.T0.Add(time.Second)
	later.Snapshot.Request.IssuedAt = later.Snapshot.Request.IssuedAt.Add(time.Second)
	later.Retention.AnchorAt = later.Retention.AnchorAt.Add(time.Second)
	later.Retention.ExpiresAt = later.Retention.ExpiresAt.Add(time.Second)
	later.Retention.DeleteBy = later.Retention.DeleteBy.Add(time.Second)
	accepted, err := CompileContext(later, now)
	if err != nil || accepted.ScopeDigest != digest {
		t.Fatal("acceptance clock changed reviewed source/window", err)
	}
	later.Snapshot.Request.MaxBytes /= 2
	if _, err = CompileContext(later, now); err == nil {
		t.Fatal("manual scope authorized a different output ceiling")
	}
	in.Snapshot.RecordingSaveScope = nil
	if _, err = CompileContext(in, now); err == nil {
		t.Fatal("manual save went through automatic source-window schema")
	}
}

func TestRecordingSaveScopeRejectsBroaderOrMixedSelection(t *testing.T) {
	for name, change := range map[string]func(*RecordingSaveScopeInput){
		"no history":        func(in *RecordingSaveScopeInput) { in.Sources[0].Before = 0 },
		"longer history":    func(in *RecordingSaveScopeInput) { in.Sources[0].Before = time.Minute },
		"other policy":      func(in *RecordingSaveScopeInput) { in.Sources[0].PolicyUID = "other" },
		"other execution":   func(in *RecordingSaveScopeInput) { in.Sources[0].ExecutionDigest = artifact.Digest{99} },
		"invalid initiator": func(in *RecordingSaveScopeInput) { in.Requester = identity.Principal{} },
		"duplicate source":  func(in *RecordingSaveScopeInput) { in.Sources = append(in.Sources, in.Sources[0]) },
		"incident cap": func(in *RecordingSaveScopeInput) {
			other := in.Sources[0]
			other.Original.SourceID = "00000000-0000-4000-8000-000000000074"
			other.Original.Request.PodUID = "other-pod"
			other.Original.Pin.UID = "other-pod"
			in.Sources = append(in.Sources, other)
		},
	} {
		t.Run(name, func(t *testing.T) {
			in, now := recordingSaveScopeInput(t)
			change(&in)
			if _, _, err := CompileRecordingSaveScope(in, now); err == nil {
				t.Fatal("broader save accepted")
			}
		})
	}
}

func TestRecordingSaveScopeRetainsAuthenticatedServiceInitiator(t *testing.T) {
	in, now := recordingSaveScopeInput(t)
	in.Requester = identity.Principal{Issuer: "urn:asservat:service-identities", Subject: "service:debugger", ClientID: "mcp-service", Kind: identity.Workload}
	raw, digest, err := CompileRecordingSaveScope(in, now)
	if err != nil {
		t.Fatal("supported authenticated service principal artificially narrowed", err)
	}
	read, err := ReadContextScopeIdentity(raw, digest)
	if err != nil || read.Requester == nil || *read.Requester != in.Requester || read.Actor != in.Authority.Executor {
		t.Fatal("service initiator replaced policy executor", err)
	}
}
