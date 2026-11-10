package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"encoding/json"
	"testing"
	"time"
)

type processingInventoryFixture struct {
	*processingFixture
	reads, scopeReads          int
	policyReads, recoveryReads int
	after                      func()
	scope                      value.ProcessingScope
}

func (f *processingInventoryFixture) DownloadPolicy(ctx context.Context) (value.DownloadPolicy, error) {
	f.policyReads++
	return f.processingFixture.DownloadPolicy(ctx)
}
func (f *processingInventoryFixture) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	f.recoveryReads++
	return f.processingFixture.RecoveryState(ctx)
}
func (f *processingInventoryFixture) ReadProcessingInventory(ctx context.Context, a value.ProcessingAuthority, q value.ProcessingInventoryQuery) (value.ProcessingInventoryPage, error) {
	f.reads++
	out := value.ProcessingInventoryPage{RootID: a.Policy.RootID, Epoch: processingID(9), Initialized: true, Sequence: 3, Rules: []value.ProcessingInventoryRule{{ID: processingID(8), Revision: 1, State: "restricted", Scope: f.scope, AdministrationUntil: f.now.Add(time.Hour), RetireBy: f.now.Add(2 * time.Hour)}}, ObservedAt: a.ObservedAt, ValidUntil: a.ValidUntil}
	if f.after != nil {
		f.after()
	}
	return out, nil
}
func (f *processingInventoryFixture) ResolveProcessingArtifactScope(ctx context.Context, a value.ProcessingAuthority, id string) (value.ProcessingScope, error) {
	f.scopeReads++
	if f.after != nil {
		f.after()
	}
	return f.scope, nil
}
func TestProcessingInventoryRequiresCurrentOperatorBeforeSQLAndPreservesOriginalBounds(t *testing.T) {
	for _, mode := range []string{"allowed", "ordinary-reader", "wrong-client", "post-read-role-loss", "post-read-expiry"} {
		t.Run(mode, func(t *testing.T) {
			base, changes, _ := newProcessingFixture(t)
			f := &processingInventoryFixture{processingFixture: base, scope: value.ProcessingScope{Kind: "artifact", Location: artifact.Location{ClusterID: processingID(10), ArtifactID: processingID(11), AttemptID: processingID(12)}}}
			s := ProcessingRuleInventory{RootID: changes.RootID, InstallationID: changes.InstallationID, Policies: f, Recovery: f, Inventory: f, Now: changes.Now}
			switch mode {
			case "ordinary-reader":
				f.i.Groups = nil
			case "wrong-client":
				f.i.Principal.ClientID = "unapproved"
			case "post-read-role-loss":
				f.after = func() { f.i.Groups = nil }
			case "post-read-expiry":
				f.after = func() { f.now = f.i.ValidUntil }
			}
			page, err := s.List(t.Context(), f, value.ProcessingInventoryQuery{Limit: 50})
			if mode == "allowed" {
				if err != nil || len(page.Rules) != 1 || !page.ValidUntil.Equal(base.p.FreshUntil) || f.reads != 1 || f.policyReads != 1 || f.recoveryReads != 1 {
					t.Fatal(page, err)
				}
				return
			}
			if err == nil || len(page.Rules) != 0 {
				t.Fatal("inventory survived unavailable authority", page, err)
			}
			if (mode == "ordinary-reader" || mode == "wrong-client") && f.reads != 0 {
				t.Fatal("ordinary caller reached rule SQL")
			}
		})
	}
}
func TestProcessingArtifactSelectorResolvesUnderOneOriginalAuthorityBeforeCanonicalAudit(t *testing.T) {
	base, s, _ := newProcessingFixture(t)
	f := &processingInventoryFixture{processingFixture: base, scope: value.ProcessingScope{Kind: "artifact", Location: artifact.Location{ClusterID: processingID(10), ArtifactID: processingID(11), AttemptID: processingID(12)}}}
	s.ArtifactScopes = f
	c := value.ProcessingChange{Action: "restrict_processing", RequestID: processingID(21), RuleID: processingID(22), RequestedArtifactID: processingID(11)}
	if c.Valid() || !c.ValidRequest() {
		t.Fatal("selector became a final scope")
	}
	result, err := s.Change(t.Context(), f, c)
	if err != nil || result.State != "restricted" || f.scopeReads != 1 || f.prepared.Change.RequestedArtifactID != "" || f.prepared.Change.Scope != f.scope {
		t.Fatal("canonical selected scope", result, err)
	}
	full := c
	full.RequestedArtifactID = ""
	full.Scope = f.scope
	if ProcessingRequestDigest(full) != ProcessingRequestDigest(f.prepared.Change) {
		t.Fatal("selector changed canonical request digest")
	}
	raw, err := json.Marshal(f.prepared.Change)
	if err != nil || string(raw) == "" {
		t.Fatal(err)
	}
	if again, err := s.Change(context.Background(), f, c); err != nil || again.OperationID != result.OperationID || f.begins != 1 {
		t.Fatal("same-key selector replay changed effect", again, err)
	}
}
func TestProcessingArtifactSelectorCannotSurviveExpiredLookupOrResolveForOrdinaryReader(t *testing.T) {
	for _, mode := range []string{"expired", "ordinary", "wrong-artifact"} {
		t.Run(mode, func(t *testing.T) {
			base, s, _ := newProcessingFixture(t)
			f := &processingInventoryFixture{processingFixture: base, scope: value.ProcessingScope{Kind: "artifact", Location: artifact.Location{ClusterID: processingID(10), ArtifactID: processingID(11), AttemptID: processingID(12)}}}
			s.ArtifactScopes = f
			switch mode {
			case "expired":
				f.after = func() { f.now = f.i.ValidUntil }
			case "ordinary":
				f.i.Groups = nil
			case "wrong-artifact":
				f.scope.Location.ArtifactID = processingID(99)
			}
			_, err := s.Change(t.Context(), f, value.ProcessingChange{Action: "restrict_processing", RequestID: processingID(21), RuleID: processingID(22), RequestedArtifactID: processingID(11)})
			if err == nil || f.begins != 0 || f.prepared != nil {
				t.Fatal("selector crossed original authority", err)
			}
			if mode == "ordinary" && f.scopeReads != 0 {
				t.Fatal("ordinary reader reached scope resolver")
			}
		})
	}
}
