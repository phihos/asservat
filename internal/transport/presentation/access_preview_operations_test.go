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

func (f *previewOpsFixture) DecodePermissionSourceSpec(spec []byte) (cfg.Source, error) {
	return cfg.Source{Resource: cfg.Resource{SpecDigest: artifact.Digest{5}}, ClusterID: accessCluster, Type: "namespaceMetadata", Enabled: true}, nil
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
			BeforeBasis    []struct {
				BasisUID string `json:"basis_uid"`
				Revision string `json:"revision"`
				Proposed bool   `json:"proposed"`
			} `json:"before_basis"`
			AfterBasis []struct {
				BasisUID string `json:"basis_uid"`
				Revision string `json:"revision"`
				Proposed bool   `json:"proposed"`
			} `json:"after_basis"`
		} `json:"deltas"`
		Unmatched    []map[string]string `json:"unmatched"`
		NotEvaluated []map[string]string `json:"not_evaluated"`
		Unavailable  []json.RawMessage   `json:"unavailable"`
		ListedRows   int                 `json:"listed_rows"`
		PageOffset   int                 `json:"page_offset"`
	} `json:"data"`
	NextCursor *string `json:"next_cursor"`
	size       int
	raw        []byte
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
	out.size, out.raw = len(reply.Body), reply.Body
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
	if len(got.Data.Unmatched) != 1 || got.Data.Unmatched[0]["uid"] != "gone" || got.NextCursor != nil {
		t.Fatalf("unmatched %+v", got.Data.Unmatched)
	}
	// Each side names the assignment that decided it with its revision.
	if len(d.BeforeBasis) != 1 || d.BeforeBasis[0].BasisUID != "binding-a" || d.BeforeBasis[0].Proposed || d.BeforeBasis[0].Revision != "09"+strings.Repeat("00", 31) ||
		len(d.AfterBasis) != 1 || !d.AfterBasis[0].Proposed || d.AfterBasis[0].Revision != "07"+strings.Repeat("00", 31) {
		t.Fatalf("revisions %+v / %+v", d.BeforeBasis, d.AfterBasis)
	}
}

// A PermissionSource creation is accepted, decoded and reported Indeterminate.
func TestPreviewAccessChangeSourceIndeterminate(t *testing.T) {
	f, s := newPreviewOps(t)
	source := `{"enabled":true,"clusterID":"` + accessCluster + `","type":"namespaceMetadata","namespaceSelector":{"matchLabels":{"team":"payments"}},"excludedNamespaces":["kube-system"],"role":"workload-maintainer","maxDecisionAgeSeconds":30,"maxNamespaces":10,` +
		`"protection":{"mode":"administratorManaged","reviewRef":"review"},"metadataMapping":{"field":"annotation","key":"example.invalid/owner","mode":"groupID","issuer":"https://id.example.invalid"}}`
	got, err := callPreview(t, f, s, `{"changes":[{"action":"create","kind":"PermissionSource","spec":`+source+`}]}`)
	if err != nil || got.Status != "ok" || got.Data.Complete || len(got.Data.NotEvaluated) != 1 || got.Data.NotEvaluated[0]["reason"] != "InheritanceNotAccepted" || got.Data.NotEvaluated[0]["decision"] != "Indeterminate" {
		t.Fatalf("%v %+v", err, got)
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

// A result larger than one reply is paged: every page fits the shared
// operation reply limit, the pages together list every row within the
// 256 KiB result bound, and a cursor from another result is refused.
func TestPreviewAccessChangePages(t *testing.T) {
	f, s := newPreviewOps(t)
	group := strings.Repeat("g", 256)
	f.cells = nil
	for n := range 300 {
		f.cells = append(f.cells, f.cell("wl-"+strconv.Itoa(n), group))
	}
	input := func(cursor string) string {
		in := `{"changes":[{"action":"create","kind":"AccessBinding","spec":` + denySpec(group, "Narrow") + `}]`
		if cursor != "" {
			in += `,"cursor":"` + cursor + `"`
		}
		return in + `}`
	}
	cursor, rows, pages, listedBytes := "", 0, 0, 0
	var first previewReply
	for {
		got, err := callPreview(t, f, s, input(cursor))
		if err != nil || got.Status != "ok" || got.size > contracts.InvestigationOutputLimit || got.Data.PageOffset != rows || got.Data.DeltasTotal != 600 {
			t.Fatalf("page %d: %v status=%s size=%d offset=%d", pages, err, got.Status, got.size, got.Data.PageOffset)
		}
		if pages == 0 {
			first = got
		}
		rows += len(got.Data.Deltas)
		var page struct {
			Data struct{ Deltas []json.RawMessage } `json:"data"`
		}
		if json.Unmarshal(got.raw, &page) != nil {
			t.Fatal("page")
		}
		for _, d := range page.Data.Deltas {
			listedBytes += len(d)
		}
		pages++
		if got.NextCursor == nil {
			break
		}
		cursor = *got.NextCursor
	}
	if pages < 2 || rows != first.Data.ListedRows || rows >= 600 || listedBytes > 256<<10 || listedBytes < 200<<10 {
		t.Fatalf("pages %d rows %d listed %d bytes %d", pages, rows, first.Data.ListedRows, listedBytes)
	}
	stale, err := callPreview(t, f, s, input("1:"+strings.Repeat("0", 32)))
	if err != nil || stale.Status != "error" || stale.Data.Code != "PreviewChanged" {
		t.Fatalf("foreign cursor: %v %+v", err, stale)
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
