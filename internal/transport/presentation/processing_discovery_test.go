package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

type processingDiscoveryFixture struct {
	policy   value.DownloadPolicy
	recovery artifact.RecoveryProof
	read     func(value.ProcessingAuthority, value.ProcessingDiscoveryQuery) value.ProcessingDiscoveryPage
}

func (f processingDiscoveryFixture) DownloadPolicy(context.Context) (value.DownloadPolicy, error) {
	return f.policy, nil
}

func (f processingDiscoveryFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, nil
}

func (f processingDiscoveryFixture) ReadProcessingDiscovery(_ context.Context, authority value.ProcessingAuthority, q value.ProcessingDiscoveryQuery) (value.ProcessingDiscoveryPage, error) {
	return f.read(authority, q), nil
}

func discoveryID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func TestAuditedProcessingDiscoveryGuardsMetadataAndFitsOutputBound(t *testing.T) {
	for _, mode := range []string{"operator", "ordinary-reader", "audit-intent-unavailable", "audit-result-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			s, caller, audit := auditedFixture(t)
			now, root, epoch := s.config.Now(), s.config.RootID, discoveryID(7)
			caller.i.Scopes = []string{}
			caller.i.Groups = []string{"privacy"}
			if mode == "ordinary-reader" {
				caller.i.Scopes, caller.i.Groups = []string{"evidence:read"}, []string{"maintainers"}
			}
			audit.beginFail, audit.finishFail = mode == "audit-intent-unavailable", mode == "audit-result-unavailable"
			policy := value.DownloadPolicy{RootID: root, InstallationID: root, RecoveryEpoch: epoch, Revision: caller.i.Policy, ProtectionDigest: artifact.Digest{1}, PermittedRegions: []string{}, Paths: []artifact.DownloadPath{}, Clients: []value.DownloadClient{},
				Operators: []value.ProcessingOperator{{Issuer: caller.i.Principal.Issuer, ClientID: caller.i.Principal.ClientID, Kind: "Group", ID: "privacy"}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
			reads := 0
			fixture := processingDiscoveryFixture{policy: policy, recovery: artifact.RecoveryProof{InstallationID: root, IssuerEpoch: epoch, Revision: caller.i.Policy, ObservedAt: now, FreshUntil: policy.FreshUntil}}
			fixture.read = func(a value.ProcessingAuthority, q value.ProcessingDiscoveryQuery) value.ProcessingDiscoveryPage {
				reads++
				if len(audit.intents) != 1 || !a.Valid(now) {
					t.Fatal("discovery read preceded current authority or audit intent")
				}
				page := value.ProcessingDiscoveryPage{RootID: root, Epoch: epoch, Sequence: 1, ObservedAt: a.ObservedAt, ValidUntil: a.ValidUntil}
				parents := make([]string, value.MaxProcessingParents)
				for i := range parents {
					parents[i] = discoveryID(100 + i)
				}
				for i := range q.Limit {
					page.Candidates = append(page.Candidates, value.ProcessingDiscoveryCandidate{ArtifactID: discoveryID(20 + i), CaptureID: discoveryID(40 + i), CaseID: q.CaseID, ClusterID: discoveryID(13),
						NamespaceUID: strings.Repeat("\u2028", 21) + "x", WorkloadUID: strings.Repeat("\u2028", 21) + "x", PurposeRef: strings.Repeat("\u2028", 42) + "xx", NativeType: artifact.SyscallArgumentsArtifact, DataClass: "raw", Origin: "derived", AnchorAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour), CustodyState: artifact.StoredUnpublished, Parents: parents})
				}
				page.Next.ArtifactID = page.Candidates[len(page.Candidates)-1].ArtifactID
				return page
			}
			base := s.inner.(*InvestigationOperations)
			ops, err := NewProcessingDiscoveryOperations(base.origin, s.config.Now, s.config.NewID, privacyapp.ProcessingEvidenceDiscovery{RootID: root, InstallationID: root, Policies: fixture, Recovery: fixture, Discovery: fixture, Now: s.config.Now})
			if err != nil {
				t.Fatal(err)
			}
			s.inner, err = NewInvestigationProcessingDiscoveryOperations(base, ops)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := s.Call(t.Context(), caller, processingDiscoveryOperation, json.RawMessage(`{"case_id":"`+discoveryID(15)+`"}`))
			if mode == "operator" {
				if err != nil || reads != 1 || len(reply.Body) == 0 || len(reply.Body) > contracts.InvestigationOutputLimit || len(audit.outcomes) != 1 {
					t.Fatal("operator discovery", reads, len(reply.Body), err)
				}
				out := audit.outcomes[0]
				if out.Status != "success" || out.Effect != "none" || len(out.ArtifactIDs) != value.ProcessingDiscoveryLimit || len(out.CaseIDs) != 1 || len(out.CaptureIDs) != value.ProcessingDiscoveryLimit {
					t.Fatal("discovery audit omitted exact references", out)
				}
				return
			}
			if err == nil || len(reply.Body) != 0 {
				t.Fatal("metadata escaped refusal", err)
			}
			if mode == "ordinary-reader" && (!errors.Is(err, identity.ErrDenied) || reads != 0 || len(audit.outcomes) != 1 || audit.outcomes[0].Status != "denied") {
				t.Fatal("ordinary reader reached discovery or denial was not audited", reads, err)
			}
			if mode == "audit-intent-unavailable" && reads != 0 || mode == "audit-result-unavailable" && reads != 1 {
				t.Fatal("wrong audit boundary", reads)
			}
		})
	}
}
