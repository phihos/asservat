package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

const previewInstallation = "11111111-2222-4333-8444-555555555555"

type previewOpsFixture struct {
	now    time.Time
	groups []string
	issuer string
	cells  []cfg.PreviewCell
}

func (f *previewOpsFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	return identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "admin", ClientID: "console", Kind: identity.Human}, Groups: f.groups, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, VerifiedAt: f.now, ValidUntil: f.now.Add(30 * time.Second)}, nil
}
func (f *previewOpsFixture) FleetAdministration(context.Context) (fleet.Administration, error) {
	return fleet.Administration{InstallationID: previewInstallation, IssuerEpoch: previewInstallation, Issuer: "https://id.example.invalid", Revision: identity.Revision{UID: "fleet", Generation: 1, Digest: artifact.Digest{4}}, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second),
		Clients: []string{"console"}, Groups: []string{"platform-admins"}, DeliveryProfiles: []string{"kv"}, MaxActiveBootstraps: 1, MaxBootstrapHistory: 1, MaxClusters: 1}, nil
}
func (f *previewOpsFixture) PreviewProjections(context.Context, cfg.PreviewRead) (cfg.PreviewSnapshot, error) {
	return cfg.PreviewSnapshot{Cells: f.cells, Unmatched: []cfg.PreviewBasis{{Kind: "AccessBinding", UID: "gone"}}}, nil
}
func (f *previewOpsFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return artifact.RecoveryProof{InstallationID: previewInstallation, IssuerEpoch: previewInstallation, Revision: identity.Revision{UID: "r", Generation: 1, Digest: artifact.Digest{3}}, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}, nil
}

// DecodeAccessBindingSpec stands in for the Kubernetes adapter's schema
// decoder (the operation contract has already applied the AccessBinding
// schema); a reason of "invalid" fails as the adapter's own checks would.
func (f *previewOpsFixture) DecodeAccessBindingSpec(spec []byte) (cfg.Binding, error) {
	var in struct {
		Effect   string        `json:"effect"`
		Subjects []cfg.Subject `json:"subjects"`
		Roles    []string      `json:"roles"`
		Reason   string        `json:"reason"`
	}
	if json.Unmarshal(spec, &in) != nil || in.Reason == "invalid" {
		return cfg.Binding{}, cfg.ErrInvalid
	}
	return cfg.Binding{Resource: cfg.Resource{SpecDigest: artifact.Digest{7}}, Effect: in.Effect, Subjects: in.Subjects, Roles: in.Roles,
		Scope: cfg.Scope{ClusterID: accessCluster, Namespace: cfg.NamespaceRef{Name: "payments", UID: "ns"}}}, nil
}

// denySpec is a complete AccessBinding spec denying evidence-reader to group.
func denySpec(group, reason string) string {
	return `{"effect":"Deny","subjects":[{"kind":"Group","issuer":"https://id.example.invalid","id":"` + group + `"}],"roles":["evidence-reader"],` +
		`"scope":{"clusterID":"` + accessCluster + `","namespaceRef":{"name":"payments","uid":"ns"}},"reason":"` + reason + `"}`
}

func (f *previewOpsFixture) cell(workload, group string) cfg.PreviewCell {
	n := f.now
	t := authorization.Target{ClusterID: accessCluster, NamespaceUID: "ns", WorkloadUID: workload, PodUID: workload}
	a := artifact.AudienceAssignment{Kind: "Group", Issuer: f.issuer, SubjectID: group, Role: "evidence-reader", BasisKind: "AccessBinding", BasisUID: "binding-a", AssignmentID: "44444444-5555-4666-8777-888888888888", BasisDigest: artifact.Digest{9}}
	p := authorization.Projection{Target: t, Revision: identity.Revision{UID: "permissions", Generation: 1, Digest: artifact.Digest{2}}, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: n, DeniesFreshUntil: n.Add(30 * time.Second),
		Allows: []authorization.CurrentAssignment{{Audience: a, ObservedAt: n, FreshUntil: n.Add(30 * time.Second)}}}
	return cfg.PreviewCell{Target: t, Projection: p}
}

func newPreviewOps(t *testing.T) (*previewOpsFixture, *AccessPreviewOperations) {
	f := &previewOpsFixture{now: time.Now().UTC(), groups: []string{"platform-admins"}, issuer: "https://id.example.invalid"}
	f.cells = []cfg.PreviewCell{f.cell(cfg.OtherWorkloads, "team-a")}
	service := authapp.AccessPreviewer{InstallationID: previewInstallation, Administration: f, Projections: f, Decoder: f, Recovery: f, Clusters: []string{accessCluster}, Now: func() time.Time { return f.now }}
	s, err := NewAccessPreviewOperations("https://asservat.example.invalid", func() time.Time { return f.now }, func() string { return "88888888-8888-4888-8888-888888888888" }, service)
	if err != nil {
		t.Fatal(err)
	}
	return f, s
}

type previewReply struct {
	Status string `json:"status"`
	Data   struct {
		Code        string `json:"code"`
		Complete    bool   `json:"complete"`
		DeltasTotal int    `json:"deltas_total"`
		Deltas      []struct {
			OtherWorkloads bool              `json:"other_workloads"`
			Subject        map[string]string `json:"subject"`
			Operation      string            `json:"operation"`
			Before, After  string
			AfterUnmet     string `json:"after_unmet"`
		} `json:"deltas"`
		Unmatched []map[string]string `json:"unmatched"`
	} `json:"data"`
}

func callPreview(t *testing.T, f *previewOpsFixture, s *AccessPreviewOperations, input string) (previewReply, error) {
	t.Helper()
	var out previewReply
	reply, err := s.Call(context.Background(), f, "preview_access_change", json.RawMessage(input))
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(reply.Body, &out); err != nil {
		t.Fatal(err)
	}
	return out, nil
}

var denyTeamA = `{"changes":[{"action":"create","kind":"AccessBinding","spec":` + denySpec("team-a", "Incident review") + `},{"action":"delete","kind":"AccessBinding","uid":"gone"}]}`

// ADR-237: the reply validates against the generated contract and reports
// the evaluator's Allow -> Deny change for the denied group.
func TestPreviewAccessChangeReply(t *testing.T) {
	f, s := newPreviewOps(t)
	got, err := callPreview(t, f, s, denyTeamA)
	if err != nil || got.Status != "ok" || !got.Data.Complete || got.Data.DeltasTotal != 2 || len(got.Data.Deltas) != 2 {
		t.Fatalf("%v %+v", err, got)
	}
	d := got.Data.Deltas[0]
	if !d.OtherWorkloads || d.Subject["id"] != "team-a" || d.Operation != "read" || d.Before != "Allow" || d.After != "Deny" || d.AfterUnmet != "ExplicitDeny" {
		t.Fatalf("delta %+v", d)
	}
	if len(got.Data.Unmatched) != 1 || got.Data.Unmatched[0]["uid"] != "gone" {
		t.Fatalf("unmatched %+v", got.Data.Unmatched)
	}
}

func TestPreviewAccessChangeNonAdministrator(t *testing.T) {
	f, s := newPreviewOps(t)
	f.groups = []string{"team-a"}
	got, err := callPreview(t, f, s, denyTeamA)
	if err != nil || got.Status != "error" || got.Data.Code != "AdministratorRequired" || len(got.Data.Deltas) != 0 {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestPreviewAccessChangeInvalidInput(t *testing.T) {
	f, s := newPreviewOps(t)
	for _, input := range []string{
		`{"changes":[]}`,
		`{"changes":[{"action":"create","kind":"AccessBinding"}]}`,
		`{"changes":[{"action":"create","kind":"AccessBinding","spec":{"effect":"Deny"}}]}`,
		`{"changes":[{"action":"delete","kind":"AccessBinding","uid":"a","spec":{}}]}`,
		`{"changes":[{"action":"create","kind":"PermissionSource","spec":{}}]}`,
	} {
		if _, err := callPreview(t, f, s, input); !errors.Is(err, contracts.ErrInvestigationWire) {
			t.Fatalf("%s: %v", input, err)
		}
	}
	got, err := callPreview(t, f, s, `{"changes":[{"action":"create","kind":"AccessBinding","spec":`+denySpec("team-a", "invalid")+`}]}`)
	if err != nil || got.Status != "error" || got.Data.Code != "InvalidProposal" {
		t.Fatalf("%v %+v", err, got)
	}
}

// Long subject IDs never push the reply beyond the shared output limit; the
// total still counts every change.
func TestPreviewAccessChangeReplyBudget(t *testing.T) {
	f, s := newPreviewOps(t)
	group := strings.Repeat("g", 256)
	f.cells = nil
	for n := range 40 {
		f.cells = append(f.cells, f.cell("wl-"+strconv.Itoa(n), group))
	}
	got, err := callPreview(t, f, s, `{"changes":[{"action":"create","kind":"AccessBinding","spec":`+denySpec(group, "Narrow")+`}]}`)
	if err != nil || got.Status != "ok" || got.Data.DeltasTotal != 80 || len(got.Data.Deltas) == 0 || len(got.Data.Deltas) >= 64 {
		t.Fatalf("%v total=%d rows=%d", err, got.Data.DeltasTotal, len(got.Data.Deltas))
	}
}

// The contract keeps the administrator preview off MCP (REQ-PER-002: no admin
// tools on evidence MCP); explain_access stays on both transports.
func TestPreviewAccessChangeIsBrowserOnly(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	preview, ok := wire.Tool("preview_access_change")
	explain, _ := wire.Tool("explain_access")
	if !ok || preview.MCP() || !explain.MCP() {
		t.Fatalf("preview MCP=%t explain MCP=%t", preview.MCP(), explain.MCP())
	}
}
