package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	catalogapp "asservat.local/asservat/internal/application/catalog"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
)

var _ ContextCaseUseCase = catalogapp.ContextCaseService{}

const caseID = "00000000-0000-4000-8000-000000000080"
const artifactID = "00000000-0000-4000-8000-000000000081"
const caseInput = `{"case_id":"` + caseID + `"}`

func TestCaseProjectionProfileKeepsNativeKindAndRawClass(t *testing.T) {
	s, f, current := caseOperationsFixture(t)
	current.i.Scopes = []string{"evidence:read"}
	f.view.Artifacts[0].EvidenceType = "profile"
	f.view.Artifacts[0].DataClass = "raw"
	reply, err := s.Call(t.Context(), current, "get_case", []byte(caseInput))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Data ContextCaseData `json:"data"`
	}
	if err := json.Unmarshal(reply.Body, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Data.Artifacts) != 1 || envelope.Data.Artifacts[0].Kind != "profile" || envelope.Data.Artifacts[0].DataClass != "raw" {
		t.Fatal("profile was mislabeled as another native artifact", envelope.Data.Artifacts)
	}
}

func TestCaseProjectionDiscriminatesVerifiedNativeFormat(t *testing.T) {
	s, f, current := caseOperationsFixture(t)
	current.i.Scopes = []string{"evidence:read"}
	for _, tc := range []struct{ name, evidence, native, class, want string }{
		{"arguments", "syscallTrace", artifact.SyscallArgumentsArtifact, "raw", artifact.SyscallArgumentsFormat},
		{"syscall-metadata", "syscallTrace", artifact.SyscallRecordsArtifact, "metadata", artifact.SyscallRecordsFormat},
		{"packet-raw", "packetCapture", artifact.RawPCAPNGArtifact, "raw", artifact.RawPCAPNGFormat},
		{"packet-headers", "packetCapture", artifact.PCAPNGArtifact, "metadata", artifact.PCAPNGFormat},
		{"http-extract", "packetCapture", artifact.HTTPHeadersArtifact, "extract", artifact.HTTPHeadersFormat},
		{"pprof", "profile", artifact.PprofArtifact, "raw", artifact.PprofFormat},
		{"go-trace", "profile", artifact.GoTraceArtifact, "raw", artifact.GoTraceFormat},
		{"context", "context", artifact.PodStatusArtifact, "metadata", artifact.ContextFormat},
		{"context-raw", "context", artifact.PodStatusArtifact, "raw", artifact.ContextFormat},
		{"unknown-native", "profile", "unknown", "raw", ""},
		{"wrong-evidence", "profile", artifact.SyscallArgumentsArtifact, "raw", ""},
		{"wrong-class", "syscallTrace", artifact.SyscallArgumentsArtifact, "metadata", ""},
		{"profile-wrong-class", "profile", artifact.PprofArtifact, "metadata", ""},
		{"packet-wrong-class", "packetCapture", artifact.PCAPNGArtifact, "raw", ""},
		{"http-wrong-class", "packetCapture", artifact.HTTPHeadersArtifact, "metadata", ""},
		{"unknown-evidence", "unknown", artifact.PodStatusArtifact, "metadata", ""},
		{"legacy-untyped", "", artifact.PodStatusArtifact, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.view.Artifacts[0].EvidenceType, f.view.Artifacts[0].DataClass, f.view.Artifacts[0].NativeType = tc.evidence, tc.class, tc.native
			reply, err := s.Call(t.Context(), current, "get_case", []byte(caseInput))
			if err != nil {
				t.Fatal(err)
			}
			if err = s.contracts.ValidateOutput("get_case", reply.Body); err != nil {
				t.Fatal("public case schema", err)
			}
			var envelope struct{ Data ContextCaseData }
			if json.Unmarshal(reply.Body, &envelope) != nil || len(envelope.Data.Artifacts) != 1 {
				t.Fatal("incorrect public case", string(reply.Body))
			}
			a := envelope.Data.Artifacts[0]
			if a.NativeFormat != tc.want || strings.Contains(string(reply.Body), `"native_format"`) != (tc.want != "") {
				t.Fatal("incorrect verified format", string(reply.Body))
			}
			if a.DataClass != listedDataClass(tc.class) || !slices.Equal(a.HandlingNotice.MayContain, listedMayContain(tc.class)) || !a.HandlingNotice.ManagedCopiesOnly || a.HandlingNotice.ExternalCopiesRecallable {
				t.Fatal("native format changed data handling", a)
			}
		})
	}
}

// Synthetic service data qualifies transport projection only, never the C-16
// authorizer, outcome audit, publication or native evidence access.
type caseProjectionFixture struct {
	view  catalog.ContextCase
	err   error
	calls int
	after func()
}

func (f *caseProjectionFixture) GetContextCase(_ context.Context, _ identities.CurrentIdentity, id string) (catalog.ContextCase, error) {
	f.calls++
	if id != caseID {
		return catalog.ContextCase{}, catalog.ErrUnavailable
	}
	if f.after != nil {
		f.after()
	}
	return f.view, f.err
}
func caseOperationsFixture(t *testing.T) (*ContextCaseOperations, *caseProjectionFixture, *contextOperationFixture) {
	t.Helper()
	_, current := operationFixture(t, false)
	now := current.i.VerifiedAt
	f := &caseProjectionFixture{view: catalog.ContextCase{CaseID: caseID, ObservedAt: now, ValidUntil: now.Add(time.Second), Artifacts: []catalog.ContextCaseArtifact{{ArtifactID: artifactID, CaptureID: "00000000-0000-4000-8000-000000000082", Target: authorization.Target{ClusterID: "00000000-0000-4000-8000-000000000083", NamespaceUID: "private-namespace", WorkloadUID: "private-workload", PodUID: "private-pod"}, Version: artifact.Digest{9}, ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}}}}
	s, e := NewContextCaseOperations(ContextCaseOperationsConfig{PublicOrigin: "https://console.invalid", Now: func() time.Time { return now }, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f)
	if e != nil {
		t.Fatal(e)
	}
	return s, f, current
}
func TestCaseProjectionUsesVerifiedVersionAndEffectiveHandlingDates(t *testing.T) {
	s, f, current := caseOperationsFixture(t)
	current.i.Scopes = []string{"evidence:read"}
	out, err := s.Call(t.Context(), current, "get_case", []byte(caseInput))
	if err != nil || f.calls != 1 || !out.ValidUntil.Equal(f.view.ValidUntil) {
		t.Fatalf("case failed: %v", err)
	}
	var result struct {
		Status string
		Data   ContextCaseData
	}
	if json.Unmarshal(out.Body, &result) != nil || result.Status != "ok" || result.Data.Case.Access != "ordinary" || result.Data.Case.Status != "Ready" || len(result.Data.Artifacts) != 1 || len(result.Data.Timeline) != 0 {
		t.Fatalf("wrong projection: %s", out.Body)
	}
	a := result.Data.Artifacts[0]
	if a.ArtifactID != artifactID || a.Digest != hash(f.view.Artifacts[0].Version) || a.Kind != "pod-status" || !a.ExpiresAt.Equal(f.view.Artifacts[0].ExpiresAt) || !a.HandlingNotice.ExpiresAt.Equal(a.ExpiresAt) || !a.HandlingNotice.DeleteBy.Equal(f.view.Artifacts[0].DeleteBy) || !a.HandlingNotice.AsOf.Equal(f.view.ObservedAt) {
		t.Fatal("incorrect version or dates")
	}
	for _, private := range []string{"private-namespace", "private-workload", "private-pod", "filename", "sha256", "capture_id", "title", "updated_at", "handlingPolicyRef", "content_path"} {
		if strings.Contains(string(out.Body), private) {
			t.Fatal("fabricated or private metadata", private)
		}
	}
	for _, op := range []string{"prepare_artifact_download", "get_artifact_download", "cancel_artifact_download", "request_capture"} {
		if _, ok := s.Tool(op); ok {
			t.Fatal("unavailable service advertised", op)
		}
	}
}
func TestCaseProjectionRejectsInputsBeforeLookupAndNormalizesFailures(t *testing.T) {
	for _, bad := range []string{`{}`, `{"case_id":"no"}`, `{"case_id":"` + caseID + `","include_raw":true}`, `{"case_id":"` + caseID + `","case_id":"` + caseID + `"}`} {
		s, f, current := caseOperationsFixture(t)
		if _, err := s.Call(t.Context(), current, "get_case", []byte(bad)); !errors.Is(err, contracts.ErrInvestigationWire) || f.calls != 0 {
			t.Fatal("invalid input reached service")
		}
	}
	s, f, current := caseOperationsFixture(t)
	var first string
	for _, failure := range []error{catalog.ErrUnavailable, errors.New("private SQL failed"), identity.ErrDenied, errors.New("case not found")} {
		f.err = failure
		out, err := s.Call(t.Context(), current, "get_case", []byte(caseInput))
		if err != nil || !strings.Contains(string(out.Body), `"status":"error"`) || strings.Contains(string(out.Body), caseID) || strings.Contains(string(out.Body), artifactID) {
			t.Fatalf("error exposed existence: %s %v", out.Body, err)
		}
		if first == "" {
			first = string(out.Body)
		} else if string(out.Body) != first {
			t.Fatal("different error revealed lookup outcome")
		}
	}
	current.i.Scopes = nil
	calls := f.calls
	if _, err := s.Call(t.Context(), current, "get_case", []byte(caseInput)); err == nil || f.calls != calls {
		t.Fatal("scope denied after lookup")
	}
}
func TestCaseProjectionRejectsInvalidAndOversizedServiceOutput(t *testing.T) {
	for _, which := range []string{"different case", "duplicate", "no artifacts", "zero deadline", "expired", "retention", "no version", "oversize"} {
		t.Run(which, func(t *testing.T) {
			s, f, current := caseOperationsFixture(t)
			switch which {
			case "different case":
				f.view.CaseID = artifactID
			case "duplicate":
				f.view.Artifacts = append(f.view.Artifacts, f.view.Artifacts[0])
			case "no artifacts":
				f.view.Artifacts = nil
			case "zero deadline":
				f.view.ValidUntil = time.Time{}
			case "expired":
				f.view.ValidUntil = f.view.ObservedAt
			case "retention":
				f.view.Artifacts[0].DeleteBy = f.view.Artifacts[0].ExpiresAt
			case "no version":
				f.view.Artifacts[0].Version = artifact.Digest{}
			case "oversize":
				original := f.view.Artifacts[0]
				for i := 1; i < 100; i++ {
					a := original
					a.ArtifactID = stringID(i)
					f.view.Artifacts = append(f.view.Artifacts, a)
				}
			}
			out, err := s.Call(t.Context(), current, "get_case", []byte(caseInput))
			if err == nil || len(out.Body) != 0 {
				t.Fatal("invalid metadata delivered", which)
			}
		})
	}
}
func stringID(i int) string {
	return "10000000-0000-4000-8000-" + strings.Repeat("0", 10) + string([]byte{'0' + byte(i/10), '0' + byte(i%10)})
}
func TestCaseProjectionRetainsOriginalAndShortenedFinalDeadline(t *testing.T) {
	s, f, current := caseOperationsFixture(t)
	original := f.view.ValidUntil
	f.after = func() { current.i.ValidUntil = f.view.ObservedAt.Add(500 * time.Millisecond) }
	out, err := s.Call(t.Context(), current, "get_case", []byte(caseInput))
	if err != nil || !out.ValidUntil.Equal(current.i.ValidUntil) || !out.ValidUntil.Before(original) {
		t.Fatal("final identity shortening ignored", err)
	}
	s, f, current = caseOperationsFixture(t)
	now := f.view.ObservedAt
	s.config.Now = func() time.Time { return now }
	calls := 0
	current.afterResolve = func() {
		calls++
		if calls == 2 {
			now = f.view.ValidUntil
		}
	}
	out, err = s.Call(t.Context(), current, "get_case", []byte(caseInput))
	if err == nil || len(out.Body) != 0 {
		t.Fatal("final identity check renewed case deadline")
	}
	s, f, current = caseOperationsFixture(t)
	f.after = func() { current.revoke = true }
	if out, err = s.Call(t.Context(), current, "get_case", []byte(caseInput)); err == nil || len(out.Body) != 0 {
		t.Fatal("revoked identity received metadata")
	}
	s, f, current = caseOperationsFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	f.after = cancel
	if out, err = s.Call(ctx, current, "get_case", []byte(caseInput)); err == nil || len(out.Body) != 0 {
		t.Fatal("cancelled request delivered")
	}
}
func TestInvestigationCompositionExposesOnlyConfiguredCapabilities(t *testing.T) {
	captures, _ := operationFixture(t, false)
	cases, _, current := caseOperationsFixture(t)
	both, err := NewInvestigationOperations(captures, cases)
	if err != nil || len(both.ToolNames()) != 5 {
		t.Fatal("composition failed", err)
	}
	if _, ok := both.Tool("request_capture"); ok {
		t.Fatal("disabled capture advertised")
	}
	out, err := both.Call(t.Context(), current, "request_capture", []byte(wireRequest))
	if err != nil || !strings.Contains(string(out.Body), "CollectionDisabled") || !BrowserOperationSupported(both, "request_capture") {
		t.Fatal("disabled browser explanation lost")
	}
	only, err := NewInvestigationOperations(nil, cases)
	if err != nil || len(only.ToolNames()) != 1 || BrowserOperationSupported(only, "request_capture") {
		t.Fatal("case-only captures became available")
	}
	if _, err = only.Call(t.Context(), current, "request_capture", []byte(wireRequest)); !errors.Is(err, contracts.ErrInvestigationWire) {
		t.Fatal("case-only hidden capture dispatch")
	}
	names := only.ToolNames()
	names[0] = "prepare_artifact_download"
	if only.ToolNames()[0] != "get_case" {
		t.Fatal("caller changed operation set")
	}
	if _, err = NewInvestigationOperations(nil, nil); err == nil {
		t.Fatal("empty set admitted")
	}
	cases.config.PublicOrigin = "https://other.invalid"
	if _, err = NewInvestigationOperations(captures, cases); err == nil {
		t.Fatal("mixed origins admitted")
	}
}

// ADR-279: a raw packet capture is listed as raw with its broader content
// notice, within the get_case output contract.
func TestCaseProjectionLabelsRawPacketCaptures(t *testing.T) {
	s, f, current := caseOperationsFixture(t)
	current.i.Scopes = []string{"evidence:read"}
	f.view.Artifacts[0].EvidenceType, f.view.Artifacts[0].DataClass = "packetCapture", "raw"
	out, err := s.Call(t.Context(), current, "get_case", []byte(caseInput))
	if err != nil {
		t.Fatal(err)
	}
	var result struct{ Data ContextCaseData }
	if json.Unmarshal(out.Body, &result) != nil || len(result.Data.Artifacts) != 1 {
		t.Fatalf("%s", out.Body)
	}
	a := result.Data.Artifacts[0]
	if a.DataClass != "raw" || !slices.Contains(a.HandlingNotice.MayContain, "userContent") {
		t.Fatalf("raw listing %+v", a)
	}
}
