package privacy

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

func processingID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

// Synthetic current source and durable decision fixture. No test value
// qualifies deployment regions, identity groups or SQL completeness.
type processingFixture struct {
	now                time.Time
	i                  identity.Identity
	p                  value.DownloadPolicy
	prepared           *ProcessingDecision
	receipt            *value.ProcessingReceipt
	applies            int
	policyObservations int
	lost               bool
}

func (f *processingFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	return f.i, nil
}
func (f *processingFixture) DownloadPolicy(context.Context) (value.DownloadPolicy, error) {
	f.policyObservations++
	return f.p, nil
}

// ApplyProcessing stores the decision once; a replay returns its receipt.
func (f *processingFixture) ApplyProcessing(_ context.Context, a value.ProcessingAuthority, d ProcessingDecision) (value.ProcessingReceipt, error) {
	if !a.Valid(f.now) || !d.Valid() {
		return value.ProcessingReceipt{}, value.ErrUnavailable
	}
	if f.prepared != nil {
		if f.prepared.Change != d.Change {
			return value.ProcessingReceipt{}, value.ErrConflict
		}
		return *f.receipt, nil
	}
	f.applies++
	f.prepared = &d
	f.receipt = &value.ProcessingReceipt{RootID: a.Policy.RootID, Epoch: processingID(7), RequestID: d.Change.RequestID, OperationID: d.Change.RequestID, Sequence: 2, ObservedAt: a.ObservedAt, ValidUntil: a.ValidUntil}
	if d.Change.Action == value.RequestEarlyErasure {
		f.receipt.State = "erasureRequested"
	} else {
		f.receipt.RuleID = d.Change.RuleID
		f.receipt.Revision = d.Change.ExpectedRevision + 1
		f.receipt.State = "restricted"
		if d.Change.Action == "release_processing" {
			f.receipt.State = "released"
		}
	}
	if f.lost {
		return value.ProcessingReceipt{}, value.ErrUnavailable
	}
	return *f.receipt, nil
}
func newProcessingFixture(t *testing.T) (*processingFixture, ProcessingChanges, value.ProcessingChange) {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	root := processingID(1)
	rev := identity.Revision{UID: processingID(2), Generation: 1, Digest: artifact.Digest{1}}
	i := identity.Identity{Principal: identity.Principal{Issuer: "https://identity.invalid", ClientID: "console", Subject: "privacy-operator", Kind: identity.Human}, Groups: []string{"privacy"}, Scopes: []string{"evidence:read"}, Policy: rev, VerifiedAt: n, ValidUntil: n.Add(5 * time.Second)}
	f := &processingFixture{now: n, i: i, p: value.DownloadPolicy{RootID: root, InstallationID: root, RecoveryEpoch: processingID(3), Revision: rev, ProtectionDigest: artifact.Digest{2}, PermittedRegions: []string{}, Paths: []artifact.DownloadPath{}, Clients: []value.DownloadClient{}, Operators: []value.ProcessingOperator{{Issuer: i.Principal.Issuer, ClientID: i.Principal.ClientID, Kind: "Group", ID: "privacy"}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}}
	service := ProcessingChanges{RootID: root, InstallationID: root, Policies: f, Decisions: f, Now: func() time.Time { return f.now }}
	return f, service, value.ProcessingChange{RequestID: processingID(4), RuleID: processingID(8), Action: "restrict_processing", Scope: value.ProcessingScope{Kind: "artifact", Location: artifact.Location{ClusterID: processingID(9), ArtifactID: processingID(10), AttemptID: processingID(11)}}}
}
func TestProcessingDecisionAppliesOnceUnderOneAuthority(t *testing.T) {
	f, s, c := newProcessingFixture(t)
	out, e := s.Change(context.Background(), f, c)
	if e != nil || !out.Valid(f.now) || out.State != "restricted" || f.applies != 1 || f.policyObservations != 1 {
		t.Fatal("decision", out, e, f.applies, f.policyObservations)
	}
	if f.prepared.CreatedAt != f.now || f.prepared.RequestUntil.After(f.p.FreshUntil) {
		t.Fatal("decision interval exceeds the original authority")
	}
}

type erasureArtifactScope struct{ location artifact.Location }

func (s erasureArtifactScope) ResolveProcessingArtifactScope(_ context.Context, _ value.ProcessingAuthority, artifactID string) (value.ProcessingScope, error) {
	if !authorization.UUID(artifactID) || artifactID != s.location.ArtifactID {
		return value.ProcessingScope{}, value.ErrUnavailable
	}
	return value.ProcessingScope{Kind: "artifact", Location: s.location}, nil
}

func TestProcessingErasureNamesExactArtifactAndReplays(t *testing.T) {
	f, service, change := newProcessingFixture(t)
	location := artifact.Location{ClusterID: processingID(10), ArtifactID: processingID(11), AttemptID: processingID(12)}
	service.ArtifactScopes = erasureArtifactScope{location: location}
	change.Action, change.RuleID, change.Scope, change.RequestedArtifactID = value.RequestEarlyErasure, "", value.ProcessingScope{}, location.ArtifactID
	receipt, err := service.Change(t.Context(), f, change)
	if err != nil || !receipt.Valid(f.now) || receipt.State != "erasureRequested" || receipt.RuleID != "" || receipt.Revision != 0 || f.applies != 1 || f.prepared.Change.Scope.Location != location {
		t.Fatal("erasure was not an exact decision", receipt, err)
	}
	again, err := service.Change(t.Context(), f, change)
	if err != nil || again != receipt || f.applies != 1 {
		t.Fatal("erasure replay changed its original decision", again, err)
	}
	change.RuleID = processingID(13)
	if _, err := service.Change(t.Context(), f, change); err == nil || f.applies != 1 {
		t.Fatal("erasure accepted an unrelated reversible rule")
	}
}

func TestProcessingUnknownReplyRecoversOriginalByRequestID(t *testing.T) {
	f, s, c := newProcessingFixture(t)
	f.lost = true
	if _, e := s.Change(context.Background(), f, c); e == nil {
		t.Fatal("lost response called accepted")
	}
	f.lost = false
	out, e := s.Change(context.Background(), f, c)
	if e != nil || out.OperationID != c.RequestID || f.applies != 1 {
		t.Fatal("replay allocated new work", out, e, f.applies)
	}
	if f.policyObservations != 2 {
		t.Fatal("retry must observe authority once per operation", f.policyObservations)
	}
}
func TestProcessingRequiresPrivacyOperator(t *testing.T) {
	for _, why := range []string{"ordinary-owner", "client"} {
		t.Run(why, func(t *testing.T) {
			f, s, c := newProcessingFixture(t)
			switch why {
			case "ordinary-owner":
				f.i.Groups = []string{"owners"}
			case "client":
				f.i.Principal.ClientID = "other"
			}
			out, e := s.Change(context.Background(), f, c)
			if !errors.Is(e, identity.ErrDenied) || out.RequestID != "" || f.applies != 0 || f.prepared != nil {
				t.Fatal("known operator denial reached the decision", out, e)
			}
		})
	}
}
