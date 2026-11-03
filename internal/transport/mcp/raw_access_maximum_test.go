package mcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type maximumRawReview struct {
	presentation.GrantUseCase
	view authapp.GrantView
}

func (f maximumRawReview) Get(_ context.Context, _ identities.CurrentIdentity, id string) (authapp.GrantView, time.Time, error) {
	if id != f.view.Grant.ID {
		return authapp.GrantView{}, time.Time{}, authapp.ErrGrantNotFound
	}
	return f.view, time.Now().Add(5 * time.Second), nil
}
func maximumRawReviewFixture(t *testing.T) authapp.GrantView {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := func(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
	scope := authorization.RawQueryScope{CaseID: id(2), Reason: strings.Repeat("r", 512), Operations: []string{authorization.GrantDownloadOperation}, MaxBytes: 64 * 512, MaxOperations: authorization.GrantMaxResultOperations, NotAfter: now.Add(time.Hour)}
	review := authapp.RawQueryReview{CaseID: scope.CaseID, Reason: scope.Reason, Operations: scope.Operations, MaxBytes: scope.MaxBytes, MaxOperations: scope.MaxOperations, NotAfter: scope.NotAfter}
	for n := 0; n < 64; n++ {
		digest := artifact.Digest{}
		for j := range digest {
			digest[j] = 255
		}
		digest[0] = byte(n + 1)
		output := authorization.VerifiedOutput{CaptureID: id(100 + n), ActionID: strings.Repeat("a", 63), ArtifactID: id(200 + n), ArtifactDigest: digest, ExecutionDigest: artifact.Digest{2}, Target: authorization.Target{ClusterID: id(3), NamespaceUID: strings.Repeat("\\", 64), WorkloadUID: strings.Repeat("\"", 64), PodUID: strings.Repeat("u", 61) + fmt.Sprintf("%03d", n)}}
		scope.Artifacts = append(scope.Artifacts, authorization.RawQueryArtifact{Output: output, NativeBytes: 512, ExpiresAt: scope.NotAfter})
		review.Artifacts = append(review.Artifacts, authapp.RawQueryReviewArtifact{Output: output, NativeBytes: 512, ExpiresAt: scope.NotAfter, Namespace: strings.Repeat("n", 63), WorkloadKind: "Deployment", WorkloadName: strings.Repeat("w", 253), PodName: strings.Repeat("p", 253), NativeType: artifact.SyscallArgumentsArtifact})
	}
	r := authapp.GrantReview{RawQuery: &review, Deadline: scope.NotAfter}
	g := authorization.Grant{ID: id(1), RootID: id(4), Kind: authorization.GrantRawQuery, DataClass: "raw", Requester: testIdentity().Principal, RequestedAt: now, ReviewUntil: now.Add(authorization.GrantReviewWindow), Lifetime: time.Hour, RawQuery: &scope, Revision: 1, Reasons: []authorization.SensitiveReason{{ActionID: "download_artifact", Code: "rawDisclosure"}}}
	g.Scope, g.ExecutionDigest = authapp.RawQueryScopeBytes(scope)
	g.Review, _ = json.Marshal(r)
	g.ReviewDigest = authapp.ReviewDigest(g, g.Review)
	if !g.Valid() || !authapp.RawQueryScopeMatches(g) {
		t.Fatal("maximum review fixture is not a valid typed and digest-bound grant")
	}
	return authapp.GrantView{Grant: g, Phase: g.Phase(now), Review: r}
}

type rawReviewFrameObserver struct {
	next    http.RoundTripper
	maximum atomic.Int64
}

func (o *rawReviewFrameObserver) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := o.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxGrantReviewResponseBytes+1))
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	for old := o.maximum.Load(); int64(len(body)) > old; old = o.maximum.Load() {
		if o.maximum.CompareAndSwap(old, int64(len(body))) {
			break
		}
	}
	return response, nil
}
func TestMaximumRawReviewUsesActualSDKTextAndStructuredFrame(t *testing.T) {
	var handler *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	view := maximumRawReviewFixture(t)
	operations, err := presentation.NewGrantOperations(server.URL, time.Now, func() string { return "00000000-0000-4000-8000-000000000099" }, maximumRawReview{view: view})
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) { return testIdentity(), nil }), operations)
	if err != nil {
		t.Fatal(err)
	}
	handler.Report = func(s string) { t.Log("MCP stage:", s) }
	observer := &rawReviewFrameObserver{next: bearerTransport{server.Client().Transport}}
	hc := *server.Client()
	hc.Transport = observer
	client := sdk.NewClient(&sdk.Implementation{Name: "bounded-raw-review", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: server.URL + Path, HTTPClient: &hc, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	called, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "get_grant", Arguments: map[string]any{"grant_id": view.Grant.ID}})
	if err != nil || called.IsError || len(called.Content) != 1 || called.StructuredContent == nil {
		t.Fatal("actual maximum SDK review call", err, called)
	}
	text, ok := called.Content[0].(*sdk.TextContent)
	if !ok {
		t.Fatal("missing text compatibility")
	}
	var fromText, fromStructured map[string]any
	structured, _ := json.Marshal(called.StructuredContent)
	if json.Unmarshal([]byte(text.Text), &fromText) != nil || json.Unmarshal(structured, &fromStructured) != nil || !reflect.DeepEqual(fromText, fromStructured) {
		t.Fatal("SDK text and structured result differ")
	}
	if fromText["status"] != "ok" {
		t.Fatal("maximum review refused", text.Text)
	}
	data := fromText["data"].(map[string]any)
	raw := data["raw_access"].(map[string]any)
	rows := raw["artifacts"].([]any)
	if len(rows) != 64 || raw["artifact_count"] != float64(64) {
		t.Fatal("selected artifacts omitted")
	}
	for n, row := range rows {
		got := row.(map[string]any)
		want := view.Review.RawQuery.Artifacts[n]
		target := got["target"].(map[string]any)
		if got["artifact_id"] != want.Output.ArtifactID || got["capture_id"] != want.Output.CaptureID || got["digest"] != hex.EncodeToString(want.Output.ArtifactDigest[:]) || got["execution_digest"] != hex.EncodeToString(want.Output.ExecutionDigest[:]) || got["native_bytes"] != float64(want.NativeBytes) || target["cluster_id"] != want.Output.Target.ClusterID || target["namespace_uid"] != want.Output.Target.NamespaceUID || target["workload_uid"] != want.Output.Target.WorkloadUID || target["pod_uid"] != want.Output.Target.PodUID || target["namespace"] != want.Namespace || target["workload_name"] != want.WorkloadName || target["pod_name"] != want.PodName {
			t.Fatal("exact artifact or target truncated", n)
		}
	}
	if len(text.Text) <= MaxResponseBytes || observer.maximum.Load() <= MaxResponseBytes || observer.maximum.Load() > MaxGrantReviewResponseBytes {
		t.Fatal("maximum fixture did not qualify dedicated larger frame", len(text.Text), observer.maximum.Load())
	}
	t.Logf("actualSDK maximum64 raw artifacts canonical bytes=%d duplicated SDK frame=%d; authority remains synthetic", len(text.Text), observer.maximum.Load())
}
func TestRawReviewFrameBudgetLeavesOrdinaryResponsesUnchanged(t *testing.T) {
	if MaxResponseBytes != 64<<10 {
		t.Fatal("ordinary MCP frame cap changed")
	}
	ordinary := newBoundedResponse()
	if _, err := ordinary.Write(make([]byte, MaxResponseBytes+1)); err == nil {
		t.Fatal("ordinary response accepted larger review size")
	}
	review := newBoundedResponse()
	review.limit = MaxGrantReviewResponseBytes
	if _, err := review.Write(make([]byte, MaxGrantReviewResponseBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := review.Write([]byte{0}); err == nil {
		t.Fatal("review frame exceeded own bound")
	}
}
