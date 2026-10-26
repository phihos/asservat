package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

type accessFixture struct {
	now       time.Time
	scopes    []string
	resolved  targets.PodResolution
	targetErr error
	allows    []authorization.CurrentAssignment
	denies    []authorization.CurrentAssignment
}

const accessCluster = "22222222-3333-4444-8555-666666666666"

func (f *accessFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	return identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "dev", ClientID: "mcp", Kind: identity.Human}, Scopes: f.scopes, Groups: []string{"team-a"}, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, VerifiedAt: f.now, ValidUntil: f.now.Add(30 * time.Second)}, nil
}
func (f *accessFixture) ResolveWorkload(context.Context, targets.WorkloadRequest) (targets.PodResolution, error) {
	return f.resolved, f.targetErr
}
func (f *accessFixture) Permissions(_ context.Context, t authorization.Target) (authorization.Projection, error) {
	n := f.now
	return authorization.Projection{Target: t, Revision: identity.Revision{UID: "permissions", Generation: 1, Digest: artifact.Digest{2}}, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: n, DeniesFreshUntil: n.Add(30 * time.Second), Allows: f.allows, Denies: f.denies}, nil
}
func (f *accessFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	id := "11111111-2222-4333-8444-555555555555"
	return artifact.RecoveryProof{InstallationID: id, IssuerEpoch: id, Revision: identity.Revision{UID: "r", Generation: 1, Digest: artifact.Digest{3}}, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}, nil
}

func newAccessFixture() (*accessFixture, *AccessOperations) {
	n := time.Now().UTC()
	f := &accessFixture{now: n, scopes: []string{"evidence:read"}}
	f.resolved = targets.PodResolution{Request: targets.Request{ClusterID: accessCluster, Namespace: configuration.NamespaceRef{Name: "payments", UID: "ns"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: "deployment"}, PodName: "api-a", PodUID: "pod"}, Pin: artifact.PinnedPod{Namespace: "payments", NamespaceUID: "ns", Name: "api-a", UID: "pod", NodeName: "worker", ControllerUID: "rs"}, NodeUID: "node", NodeBootID: "33333333-4444-4555-8666-777777777777", PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
	mine := artifact.AudienceAssignment{Kind: "Group", Issuer: "https://id.example.invalid", SubjectID: "team-a", Role: "evidence-reader", BasisKind: "AccessBinding", BasisUID: "binding-a", AssignmentID: "44444444-5555-4666-8777-888888888888", BasisDigest: artifact.Digest{9}}
	other := mine
	other.SubjectID, other.AssignmentID, other.BasisUID = "team-b", "55555555-5555-4666-8777-888888888888", "binding-b"
	f.allows = []authorization.CurrentAssignment{{Audience: mine, ObservedAt: n, FreshUntil: n.Add(30 * time.Second)}, {Audience: other, ObservedAt: n, FreshUntil: n.Add(30 * time.Second)}}
	service := authapp.AccessExplainer{InstallationID: "11111111-2222-4333-8444-555555555555", Targets: f, Permissions: f, Recovery: f, Now: func() time.Time { return f.now }}
	s, err := NewAccessOperations("https://asservat.example.invalid", func() time.Time { return f.now }, func() string { return "88888888-8888-4888-8888-888888888888" }, service)
	if err != nil {
		panic(err)
	}
	return f, s
}

func accessCall(t *testing.T, s *AccessOperations, f *accessFixture, input string) map[string]any {
	t.Helper()
	reply, err := s.CallWithContext(context.Background(), f, OperationCall{requestID: "88888888-8888-4888-8888-888888888888"}, "explain_access", json.RawMessage(input))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(reply.Body, &out); err != nil {
		t.Fatal(err)
	}
	return out["data"].(map[string]any)
}

func accessRequest(op string) string {
	b, _ := json.Marshal(map[string]any{"target_ref": map[string]string{"cluster_id": accessCluster, "namespace": "payments", "kind": "Deployment", "name": "api"}, "operation": op})
	return string(b)
}

func TestExplainAccessOperationContract(t *testing.T) {
	f, s := newAccessFixture()
	got := accessCall(t, s, f, accessRequest("read"))
	rows := got["assignments"].([]any)
	if got["decision"] != "Allow" || len(rows) != 1 || rows[0].(map[string]any)["basis_uid"] != "binding-a" || got["target"] == nil || got["valid_until"] == nil {
		t.Fatalf("allow: %v", got)
	}
	got = accessCall(t, s, f, accessRequest("download"))
	if got["decision"] != "Deny" || got["unmet"] != "ClientScopeMissing" || got["missing_scope"] != "evidence:download" {
		t.Fatalf("download without scope: %v", got)
	}
	got = accessCall(t, s, f, accessRequest("capture"))
	if got["decision"] != "Deny" || got["unmet"] != "ClientScopeMissing" {
		t.Fatalf("capture: %v", got)
	}
	f.scopes = append(f.scopes, "evidence:capture")
	got = accessCall(t, s, f, accessRequest("capture"))
	if got["decision"] != "Deny" || got["unmet"] != "NoMatchingAllow" || got["required_roles"].([]any)[0] != "workload-maintainer" || got["target"] == nil {
		t.Fatalf("reader capture: %v", got)
	}
	if _, err := s.CallWithContext(context.Background(), f, OperationCall{requestID: "88888888-8888-4888-8888-888888888888"}, "explain_access", json.RawMessage(accessRequest("delete"))); !errors.Is(err, contracts.ErrInvestigationWire) {
		t.Fatalf("unknown operation accepted: %v", err)
	}
}

// The reply for a caller without own assignments equals the reply for a
// workload that does not resolve, byte for byte.
func TestExplainAccessUndisclosedIsUniform(t *testing.T) {
	f, s := newAccessFixture()
	f.allows = f.allows[1:]
	deny := f.allows[0]
	deny.Audience.SubjectID = "team-a"
	f.denies = []authorization.CurrentAssignment{deny}
	foreign := accessCall(t, s, f, accessRequest("read"))
	f, s = newAccessFixture()
	f.targetErr = targets.ErrUnavailable
	missing := accessCall(t, s, f, accessRequest("read"))
	a, _ := json.Marshal(foreign)
	b, _ := json.Marshal(missing)
	if string(a) != string(b) || foreign["target"] != nil || len(foreign["assignments"].([]any)) != 0 {
		t.Fatalf("undisclosed replies differ:\n%s\n%s", a, b)
	}
}
