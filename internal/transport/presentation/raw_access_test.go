package presentation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

type rawGrantUseCase struct {
	*grantUseCase
	input      authapp.RawQueryRequestInput
	requestErr error
	calls      int
}

func (g *rawGrantUseCase) RequestRaw(_ context.Context, _ identities.CurrentIdentity, in authapp.RawQueryRequestInput) (authorization.Grant, bool, error) {
	g.calls++
	g.input = in
	return g.view.Grant, true, g.requestErr
}
func rawGrantView(now time.Time, count int) authapp.GrantView {
	v := grantView(now)
	g := &v.Grant
	g.Kind, g.DataClass = authorization.GrantRawQuery, "raw"
	g.Target = authorization.Target{}
	g.PreviewID, g.CaptureID = "", ""
	g.ResultAccess = nil
	g.Reasons = []authorization.SensitiveReason{{ActionID: "download_artifact", Code: "rawDisclosure"}}
	g.ResultAccessDigest = artifact.Digest{}
	g.RawQuery = &authorization.RawQueryScope{CaseID: "00000000-0000-4000-8000-000000000002", Reason: "inspect existing evidence", Operations: []string{"download_artifact"}, MaxBytes: int64(count) * 512, MaxOperations: authorization.GrantMaxResultOperations, NotAfter: now.Add(time.Hour)}
	v.Review = authapp.GrantReview{RawQuery: &authapp.RawQueryReview{CaseID: g.RawQuery.CaseID, Reason: g.RawQuery.Reason, Operations: g.RawQuery.Operations, MaxBytes: g.RawQuery.MaxBytes, MaxOperations: g.RawQuery.MaxOperations, NotAfter: g.RawQuery.NotAfter}}
	for n := 0; n < count; n++ {
		o := authorization.VerifiedOutput{ArtifactID: fmt.Sprintf("00000000-0000-4000-8000-%012d", 100+n), CaptureID: "00000000-0000-4000-8000-000000000045", ActionID: "calls", ArtifactDigest: artifact.Digest{byte(n + 1)}, ExecutionDigest: artifact.Digest{2}, Target: authorization.Target{ClusterID: "00000000-0000-4000-8000-000000000004", NamespaceUID: "ns", WorkloadUID: fmt.Sprintf("workload-%d", n), PodUID: fmt.Sprintf("pod-%d", n)}}
		g.RawQuery.Artifacts = append(g.RawQuery.Artifacts, authorization.RawQueryArtifact{Output: o, NativeBytes: 512, ExpiresAt: now.Add(time.Hour)})
		v.Review.RawQuery.Artifacts = append(v.Review.RawQuery.Artifacts, authapp.RawQueryReviewArtifact{Output: o, NativeBytes: 512, ExpiresAt: now.Add(time.Hour), NativeType: artifact.SyscallArgumentsArtifact, Namespace: "payments", WorkloadKind: "Deployment", WorkloadName: fmt.Sprintf("api-%d", n), PodName: fmt.Sprintf("pod-%d", n)})
	}
	bindRawGrantReview(&v)
	return v
}

func bindRawGrantReview(v *authapp.GrantView) {
	v.Grant.Scope, v.Grant.ExecutionDigest = authapp.RawQueryScopeBytes(*v.Grant.RawQuery)
	v.Grant.Review, _ = json.Marshal(v.Review)
	v.Grant.ReviewDigest = authapp.ReviewDigest(v.Grant, v.Grant.Review)
}

func TestRawQueryGrantPublicRequestAndReview(t *testing.T) {
	base, f := operationFixture(t, true)
	uc := &rawGrantUseCase{grantUseCase: &grantUseCase{view: rawGrantView(f.i.VerifiedAt, 2), until: f.metadataUntil}}
	if !uc.view.Grant.Valid() || !authapp.RawQueryScopeMatches(uc.view.Grant) {
		t.Fatal("invalid raw grant fixture")
	}
	s, err := NewGrantOperations("https://console.invalid", base.config.Now, func() string { return "00000000-0000-4000-8000-000000000099" }, uc)
	if err != nil {
		t.Fatal(err)
	}
	if tool, ok := s.Tool("request_raw_access"); !ok || !tool.MCP() {
		t.Fatal("raw request missing from shared transport", ok)
	}
	in := fmt.Sprintf(`{"case_id":"%s","artifact_digests":["%s"],"operations":["download_artifact"],"reason":"incident","max_bytes":1024,"expires_in_seconds":3600,"idempotency_key":"same-key"}`, uc.view.Grant.RawQuery.CaseID, hash(artifact.Digest{1}))
	reply, err := s.Call(t.Context(), f, "request_raw_access", []byte(in))
	if err != nil || !strings.Contains(string(reply.Body), `"phase":"Pending"`) || !strings.Contains(string(reply.Body), `"approval_uri":"https://console.invalid/approvals/`) {
		t.Fatalf("request: %v %s", err, reply.Body)
	}
	if uc.input.CaseID != uc.view.Grant.RawQuery.CaseID || len(uc.input.ArtifactDigests) != 1 || uc.input.ArtifactDigests[0] != (artifact.Digest{1}) || uc.input.Lifetime != time.Hour || uc.input.MaxBytes != 1024 || uc.input.IdempotencyKey != "same-key" {
		t.Fatal("request changed", uc.input)
	}
	for _, phase := range []string{"Expired", "Revoked"} {
		if phase == "Expired" {
			uc.view.Grant.RawQuery.NotAfter = f.i.VerifiedAt
		} else {
			uc.view.Grant.RevokedAt = f.i.VerifiedAt
		}
		reply, err = s.Call(t.Context(), f, "request_raw_access", []byte(in))
		if err != nil || !strings.Contains(string(reply.Body), `"phase":"`+phase+`"`) {
			t.Fatalf("replay %s: %v %s", phase, err, reply.Body)
		}
	}
	uc.requestErr = authapp.ErrRawQueryOperationUnsupported
	uc.input = authapp.RawQueryRequestInput{}
	reply, err = s.Call(t.Context(), f, "request_raw_access", []byte(strings.Replace(in, "download_artifact", "read_memory", 1)))
	if err == nil || uc.input.CaseID != "" {
		t.Fatal("unsupported runtime operation reached grant service", err)
	}
	reply, err = s.Call(t.Context(), f, "request_raw_access", []byte(strings.Replace(in, "download_artifact", "pcap_query", 1)))
	if err != nil || !strings.Contains(string(reply.Body), `"code":"UnsupportedOperation"`) {
		t.Fatalf("closed service refusal: %v %s", err, reply.Body)
	}
	uc.view = rawGrantView(f.i.VerifiedAt, 2)
	for _, name := range []string{"get_grant", "list_reviews"} {
		input := `{"grant_id":"` + uc.view.Grant.ID + `"}`
		if name == "list_reviews" {
			input = `{"view":"requested"}`
		}
		reply, err = s.Call(t.Context(), f, name, []byte(input))
		if err != nil {
			b, _ := json.Marshal(OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: "00000000-0000-4000-8000-000000000099", DataClass: "metadata", Status: "ok", Data: s.view(uc.view, f.i.Principal, true, base.config.Now()), Warnings: []string{}, Provenance: []any{}})
			t.Fatalf("%s %v; output contract: %v; %s", name, err, s.contracts.ValidateOutput(name, b), b)
		}
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(reply.Body, &envelope) != nil {
			t.Fatal("wire")
		}
		var d map[string]json.RawMessage
		if name == "list_reviews" {
			var list struct {
				Approvals []map[string]json.RawMessage `json:"approvals"`
			}
			json.Unmarshal(envelope.Data, &list)
			d = list.Approvals[0]
		} else {
			json.Unmarshal(envelope.Data, &d)
		}
		for _, field := range []string{"target", "actions", "capture_id", "preview_id", "preview_deadline", "capture_deadline_rule", "result_access", "policy", "observation_limits"} {
			if _, ok := d[field]; ok {
				t.Fatal("invented collection field", name, field)
			}
		}
		var access grantRawAccessData
		json.Unmarshal(d["raw_access"], &access)
		if access.ArtifactCount != 2 || access.MaxOperations != 10000 {
			t.Fatal(access)
		}
		if name == "get_grant" && (len(access.Artifacts) != 2 || access.Artifacts[1].Target.WorkloadUID != "workload-1" || access.Artifacts[1].NativeBytes != 512) {
			t.Fatal("lost exact target or size", access)
		}
		if name == "list_reviews" && len(access.Artifacts) != 0 {
			t.Fatal("inbox leaked full detail")
		}
	}
}

func TestRawQueryGrantPublic64Artifacts(t *testing.T) {
	base, f := operationFixture(t, true)
	uc := &rawGrantUseCase{grantUseCase: &grantUseCase{view: rawGrantView(f.i.VerifiedAt, 64), until: f.metadataUntil}}
	for n := range uc.view.Review.RawQuery.Artifacts {
		a := &uc.view.Review.RawQuery.Artifacts[n]
		a.Output.Target.NamespaceUID = strings.Repeat("a", 64)
		a.Output.Target.WorkloadUID = strings.Repeat("a", 64)
		a.Output.Target.PodUID = strings.Repeat("a", 64)
		a.Namespace = strings.Repeat("a", 63)
		a.WorkloadName = strings.Repeat("a", 253)
		a.PodName = strings.Repeat("a", 253)
		uc.view.Grant.RawQuery.Artifacts[n].Output = a.Output
	}
	bindRawGrantReview(&uc.view)
	if !uc.view.Grant.Valid() || !authapp.RawQueryScopeMatches(uc.view.Grant) {
		t.Fatal("invalid64-artifact raw grant fixture")
	}
	s, err := NewGrantOperations("https://console.invalid", base.config.Now, func() string { return "00000000-0000-4000-8000-000000000099" }, uc)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := s.Call(t.Context(), f, "get_grant", []byte(`{"grant_id":"`+uc.view.Grant.ID+`"}`))
	if err != nil || len(reply.Body) <= 24<<10 || len(reply.Body) > 256<<10 {
		t.Fatalf("64-artifact detail: %d bytes %v", len(reply.Body), err)
	}
	var out struct {
		Data grantData `json:"data"`
	}
	if json.Unmarshal(reply.Body, &out) != nil || len(out.Data.RawAccess.Artifacts) != 64 {
		t.Fatal("selection truncated")
	}
}
