package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

func compiledProfileReplayRow(t *testing.T) custodydb.ContextCapture {
	t.Helper()
	p := previewTestValue(t)
	composition := value.ProfileComposition{Components: []value.ProfileComponent{{ID: "cpu", Profile: value.ProfileRef{Catalog: "builtin", Name: "go-cpu", Version: "v1"}}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s"}
	target := targets.PodResolution{Request: p.Target, Pin: p.Pin, ExecutionClass: artifact.ContextAPIExecution, PodResourceVersion: "10", WorkloadResourceVersion: "20", ObservedAt: p.CreatedAt, FreshUntil: p.CreatedAt.Add(5 * time.Second)}
	target.Pin.NodeName = ""
	retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "set", Generation: 1, Digest: [32]byte{7}}, ObservedAt: p.CreatedAt, FreshUntil: p.CreatedAt.Add(30 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{4}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "profile", AnchorAt: p.CreatedAt}, p.CreatedAt)
	if err != nil {
		t.Fatal("retention", err)
	}
	in := value.RecorderInput{CaptureID: p.CaptureID, Executor: p.Actor, Target: target, Composition: composition, Retention: retention, Deadline: p.Deadline, NodeRecorder: true}
	_, err = planning.CompileRecorder(in, nil, p.CreatedAt)
	var needed planning.EndpointResolutionNeeded
	if !errors.As(err, &needed) {
		t.Fatal("endpoint query", err)
	}
	in.Endpoints = []targets.ProfileEndpointResolution{{Request: needed.Request, SourceKind: targets.ProfileEndpointTemplateBinding, SourceName: "go-pprof-loopback", AddressMode: "targetLoopback", Port: 6060, DeclaredPortName: "diagnostics", PathPolicy: "go-pprof/v1", DefinitionDigest: artifact.Digest{1}, EndpointDigest: artifact.Digest{2}, ResolvedAt: p.CreatedAt}}
	plan, err := planning.CompileRecorder(in, nil, p.CreatedAt)
	if err != nil {
		t.Fatal("profile compile", err)
	}
	frozen, err := planning.ProfileContextFromScope(composition, target.Request, plan.CanonicalScope)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(frozen)
	r := needed.Request
	profile := artifact.GoProfileAcquisition{SourceRef: r.SourceRef, EndpointDigest: in.Endpoints[0].EndpointDigest, Type: r.Type, Mode: r.Mode, DurationMillis: r.DurationSeconds * 1000, ForceGC: r.ForceGC, TimeoutMillis: 15000, MaxBytes: r.NativeLimit, Composition: encoded}
	row := progressFactsFixture(t, "pending").ContextCapture
	var e artifact.ContextExpectation
	if err = json.Unmarshal(row.ExpectationJson, &e); err != nil {
		t.Fatal(err)
	}
	e.ExecutionClass = artifact.ContextAPIExecution
	e.NativeType = artifact.PprofArtifact
	e.NodeUID, e.NodeBootID = "", ""
	e.Registration.NativeLimit = 16 << 20
	e.Profile = &profile
	e.DataClass = "raw"
	e.ActionID, e.RecipeDigest, e.PlanDigest = plan.Actions[0].ID, plan.RecipeDigest, plan.ScopeDigest
	if err = e.Validate(); err != nil {
		t.Fatal("expectation", err)
	}
	row.ExpectationJson, _ = json.Marshal(e)
	row.PodPinJson, _ = json.Marshal(target.Pin)
	row.ScopeJson = bytes.Clone(plan.CanonicalScope)
	row.ScopeDigest = bytes.Clone(plan.ScopeDigest[:])
	return row
}

func TestApprovedProfileRequestScopePreservesReviewedTiming(t *testing.T) {
	row := compiledProfileReplayRow(t)
	got, err := requestRecordScope(row)
	expected := previewTestValue(t).Actor
	if err != nil || !got.ApprovedAcceptance || !got.Deadline.IsZero() || got.Actor != expected {
		t.Fatal("valid compiled approved profile replay rejected", got, err)
	}
	var e artifact.ContextExpectation
	_ = json.Unmarshal(row.ExpectationJson, &e)
	for _, name := range []string{"scope-digest", "capture", "target", "malformed", "missing-approval", "unapproved-timing", "wrong-version"} {
		t.Run(name, func(t *testing.T) {
			r := row
			r.ScopeJson = bytes.Clone(row.ScopeJson)
			r.ScopeDigest = bytes.Clone(row.ScopeDigest)
			switch name {
			case "scope-digest":
				r.ScopeDigest[0] ^= 1
			case "capture":
				r.ID = r.AttemptID
			case "target":
				changed := e
				changed.WorkloadUID = "other-workload"
				r.ExpectationJson, _ = json.Marshal(changed)
			case "malformed":
				r.ScopeJson = []byte(`{`)
			default:
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(r.ScopeJson, &fields)
				switch name {
				case "missing-approval":
					delete(fields, "approval")
				case "unapproved-timing":
					delete(fields, "timing")
				case "wrong-version":
					fields["schemaVersion"] = json.RawMessage(`"unsupported/v1"`)
				}
				b, _ := json.Marshal(fields)
				canonical := jsontext.Value(b)
				if err := canonical.Canonicalize(); err != nil {
					t.Fatal(err)
				}
				r.ScopeJson = canonical
				d := sha256.Sum256(r.ScopeJson)
				r.ScopeDigest = d[:]
				changed := e
				changed.PlanDigest = d
				r.ExpectationJson, _ = json.Marshal(changed)
			}
			if _, err := requestRecordScope(r); err == nil {
				t.Fatal("mismatched historical shape accepted")
			}
		})
	}
}
