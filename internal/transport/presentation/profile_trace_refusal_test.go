package presentation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	authorizationapp "asservat.local/asservat/internal/application/authorization"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	auth "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// Synthetic current permission/publication ports compose the REAL C3 source
// authorizer, C18 coordinator and audited C20 operation. No native reader,
// worker, SQL reservation or fixture identity supplies production authority.
type traceSummaryAuthorityPorts struct {
	*bridgeFixture
	record      authorizationapp.ContextProjectionEvidence
	permissions auth.Projection
	catalogs    int
	catalogErr  error
	onCatalog   func()
}

func (p *traceSummaryAuthorityPorts) Permissions(context.Context, auth.Target) (auth.Projection, error) {
	return p.permissions, nil
}
func (p *traceSummaryAuthorityPorts) ContextProjectionEvidence(context.Context, string) (authorizationapp.ContextProjectionEvidence, error) {
	p.catalogs++
	if p.onCatalog != nil {
		p.onCatalog()
	}
	return p.record, p.catalogErr
}
func (p *traceSummaryAuthorityPorts) ResolveRetained(context.Context, privacy.Input, privacy.Deadlines, []artifact.RetentionRule) (privacy.RetainedResolution, error) {
	panic("unsupported source reached retention")
}
func (p *traceSummaryAuthorityPorts) ProjectionEnvironment(context.Context, authorizationapp.ContextProjectionEvidence, identity.Principal) (value.ContextProjectionEnvironment, error) {
	panic("unsupported source reached analyzer environment")
}

func traceSummaryBridge(t *testing.T) (*AuditedOperations, *bridgeFixture, *presentationAuditGate, *traceSummaryAuthorityPorts, *string) {
	t.Helper()
	s, f, g, p := summaryBridge(t)
	scope := f.a.Scope
	target := auth.Target{ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, PodUID: scope.PodUID}
	audience := artifact.AudienceAssignment{Kind: "Group", Issuer: f.i.Principal.Issuer, SubjectID: "team", Role: "evidence-reader", BasisKind: "AccessBinding", BasisUID: "binding", BasisDigest: artifact.Digest{1}, AssignmentID: bridgeID}
	reg := artifact.Registration{Location: artifact.Location{ClusterID: scope.ClusterID, ArtifactID: scope.ArtifactID, AttemptID: bridgeID}, StoreID: bridgeID, AllocationID: bridgeID, PoolRevision: 1, AllocationRevision: 1, NativeLimit: artifact.MaxGoTraceBytes, AnchorAt: f.now.Add(-time.Minute), WriteUntil: f.now.Add(-time.Second), ExpiresAt: f.now.Add(time.Minute), DeleteBy: f.now.Add(2 * time.Minute)}
	record := authorizationapp.ContextProjectionEvidence{CaseID: scope.CaseID, CaptureID: scope.CaptureID, PurposeRef: "diagnostics", Version: scope.Version, NativeType: artifact.GoTraceArtifact, SourceFormat: artifact.GoTraceFormat, DataClass: "raw", Audience: []artifact.AudienceAssignment{audience}, ObservedAt: f.now, ValidUntil: f.i.ValidUntil, Retained: privacy.RetainedArtifact{RootID: scope.RootID, Registration: reg, Input: privacy.Input{Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: "profile", RequestedSeconds: 120, AnchorAt: reg.AnchorAt}, OriginPolicies: []artifact.RetentionRule{{UID: "baseline", Generation: 1, Digest: artifact.Digest{1}}}, Effective: privacy.Deadlines{AnchorAt: reg.AnchorAt, ExpiresAt: reg.ExpiresAt, DeleteBy: reg.DeleteBy}}}
	if !record.Retained.Valid() {
		t.Fatal("invalid synthetic committed source facts")
	}
	ports := &traceSummaryAuthorityPorts{bridgeFixture: f, record: record, permissions: auth.Projection{Target: target, Revision: f.i.Policy, ObservedAt: f.now, FreshUntil: f.i.ValidUntil, DeniesComplete: true, DeniesObservedAt: f.now, DeniesFreshUntil: f.i.ValidUntil, Allows: []auth.CurrentAssignment{{Audience: audience, ObservedAt: f.now, FreshUntil: f.i.ValidUntil}}}}
	f.s.Results.Authority = authorizationapp.ContextProjectionAuthority{RootID: scope.RootID, Permissions: ports, Catalog: ports, Retention: ports, Environment: ports, Now: func() time.Time { return f.now }}
	stage := ""
	f.s.Results.Refused = func(_ context.Context, _ string, err error) {
		var fixed interface{ FixedStep() string }
		if errors.As(err, &fixed) {
			stage = fixed.FixedStep()
		}
	}
	adapter, err := NewContextProjectionOperations(f.s, f.s.Results)
	if err == nil {
		reads, _ := f.s.ProfileSummaries()
		adapter, err = adapter.WithProfileSummaries(reads)
	}
	if err != nil {
		t.Fatal(err)
	}
	p.adapter = adapter
	return s, f, g, ports, &stage
}

func TestProfileSummaryCommittedGoTraceReturnsSemanticUnavailableWithoutQuery(t *testing.T) {
	s, f, g, ports, stage := traceSummaryBridge(t)
	reply, err := s.Call(t.Context(), f, "get_profile_summary", summaryInput(20))
	if err != nil {
		t.Fatalf("committed goTrace becomes transport failure instead of semantic NotAvailable: err=%v stage=%s catalogs=%d admissions=%d workers=%d", err, *stage, ports.catalogs, f.admissions, f.starts)
	}
	defer reply.Close(t.Context())
	var result struct {
		Status string `json:"status"`
		Data   struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	if json.Unmarshal(reply.Body, &result) != nil || result.Status != "error" || result.Data.Code != "NotAvailable" || s.contracts.ValidateOutput("get_profile_summary", reply.Body) != nil || ports.catalogs != 1 || f.admissions+f.starts+f.reads != 0 || len(g.outcomes) != 1 || g.outcomes[0].Effect != "none" {
		t.Fatal("unsupported source consumed query or lost audited fixed refusal", string(reply.Body), ports.catalogs, f.admissions, f.starts, f.reads)
	}
}

func TestProfileSummaryPreAdmissionUnavailableDoesNotDistinguishSourcesOrAccess(t *testing.T) {
	var common []byte
	for _, mode := range []string{"trace-metadata", "unsupported-published-source", "denied", "missing", "provider-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			s, f, g, ports, _ := traceSummaryBridge(t)
			switch mode {
			case "unsupported-published-source":
				ports.record = authorizationapp.ContextProjectionEvidence{}
				ports.catalogErr = privacyapp.ErrFence
			case "denied":
				ports.permissions.Allows = nil
			case "missing":
				ports.record = authorizationapp.ContextProjectionEvidence{}
				ports.catalogErr = errors.New("private missing source detail")
			case "provider-unavailable":
				ports.record = authorizationapp.ContextProjectionEvidence{}
				ports.catalogErr = errors.New("private provider detail")
			}
			reply, err := s.Call(t.Context(), f, "get_profile_summary", summaryInput(20))
			if err != nil {
				t.Fatal("proven preadmission refusal became transport error", mode, err)
			}
			defer reply.Close(t.Context())
			if common == nil {
				common = append([]byte(nil), reply.Body...)
			} else if !bytes.Equal(common, reply.Body) {
				t.Fatal("refusal disclosed source/access/provider distinction", mode, string(reply.Body))
			}
			if f.admissions+f.starts+f.reads != 0 || len(g.outcomes) != 1 || g.outcomes[0].Effect != "none" || g.outcomes[0].Status != "unavailable" {
				t.Fatal("source refusal lost zeroeffects or unavailable audit", g.outcomes)
			}
			if mode == "denied" && ports.catalogs != 0 {
				t.Fatal("denied caller reached protected catalog")
			}
		})
	}
}

func TestProfileSummaryPreAdmissionRefusalStillRequiresAuditCurrentIdentityAndDeadline(t *testing.T) {
	for _, mode := range []string{"audit-begin", "audit-finish", "cancel-during-catalog", "final-groups-changed", "original-expiry"} {
		t.Run(mode, func(t *testing.T) {
			s, f, g, ports, _ := traceSummaryBridge(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "audit-begin":
				g.beginFail = true
			case "audit-finish":
				g.finishFail = true
			case "cancel-during-catalog":
				ports.onCatalog = cancel
			case "final-groups-changed":
				g.onFinish = func() { f.i.Groups = nil }
			case "original-expiry":
				g.onFinish = func() { f.now = f.i.ValidUntil }
			}
			reply, err := s.Call(ctx, f, "get_profile_summary", summaryInput(20))
			if err == nil || len(reply.Body) != 0 || f.admissions+f.starts+f.reads != 0 {
				t.Fatal("expired or unaudited semantic refusal escaped", mode, err, string(reply.Body))
			}
		})
	}
}

func TestProfileSummaryUnknownAndPostAdmissionErrorsRemainTransportUnavailable(t *testing.T) {
	for _, mode := range []string{"route", "attempted-admission", "worker-room", "post-admission-read"} {
		t.Run(mode, func(t *testing.T) {
			s, f, g, p := summaryBridge(t)
			switch mode {
			case "attempted-admission":
				f.queryErr = errors.New("unknown admission result")
			case "worker-room":
				f.workerErr = errors.New("unknown worker admission")
			case "post-admission-read":
				f.errorAfterRead = errors.New("unknown read result")
			}
			if mode == "route" {
				f.s.ProfileRoutes = summaryUnavailableRoute{}
				reads, _ := f.s.ProfileSummaries()
				adapter, err := NewContextProjectionOperations(f.s, f.s.Results)
				if err == nil {
					adapter, err = adapter.WithProfileSummaries(reads)
				}
				if err != nil {
					t.Fatal(err)
				}
				p.adapter = adapter
			}
			reply, err := s.Call(t.Context(), f, "get_profile_summary", summaryInput(20))
			if err == nil || len(reply.Body) != 0 {
				t.Fatal("nonclassified or attempted query became zeroeffect semantic refusal", mode, err)
			}
			if mode == "attempted-admission" && (f.admissions != 1 || len(g.outcomes) != 1 || g.outcomes[0].Effect != "unknown") {
				t.Fatal("uncertain admission was represented as no effect", f.admissions, g.outcomes)
			}
		})
	}
}

type summaryUnavailableRoute struct{}

func (summaryUnavailableRoute) ResolveProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	return value.ContextProjectionCandidate{}, errors.New("private route unavailable")
}
