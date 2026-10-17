package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// ProcessingReads cannot initialize completeness, publish lineage, remove a
// restriction or accept recovery. Its business-table privileges are SELECT only.
type ProcessingReads struct {
	ledger   *Ledger
	root     string
	recovery *RecoveryTransactionGuard
}

var _ app.DownloadProcessingReader = (*ProcessingReads)(nil)

func NewProcessingReads(ctx context.Context, pool *pgxpool.Pool, root string, recovery *RecoveryTransactionGuard) (*ProcessingReads, error) {
	if !authorization.UUID(root) || recovery == nil || recovery.root != root {
		return nil, value.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, value.ErrUnavailable
	}
	return &ProcessingReads{l, root, recovery}, nil
}
func processingRootValid(p custodydb.ProcessingRoot, installation string, now time.Time) bool {
	var b value.ProcessingBacking
	return uid(p.InstallationID) == installation && p.InitializedAt.Valid && p.InitializationID.Valid && now.Before(p.ValidUntil.Time) && json.Unmarshal(p.Backing, &b) == nil && b.Valid() && b.RootID == uid(p.RootID) && b.InstallationID == installation && b.ValidUntil.Equal(p.ValidUntil.Time) && b.RetireBy.Equal(p.RetireBy.Time) && b.MaxCaptures == p.MaxCaptures && b.MaxRules == p.MaxRules && b.MaxRootTransitions == p.MaxRootTransitions
}
func readProcessingSnapshot(ctx context.Context, q *custodydb.Queries, root, installation, issuerEpoch, artifactID string, started, until time.Time) (value.ProcessingSnapshot, custodydb.ProcessingRoot, error) {
	var zero value.ProcessingSnapshot
	p, e := q.ReadProcessingRoot(ctx, id(root))
	if e != nil {
		return zero, p, e
	}
	n, e := q.CurrentTime(ctx)
	if e != nil || !processingRootValid(p, installation, n.Time) || uid(p.IssuerEpoch) != issuerEpoch {
		return zero, p, value.ErrUnavailable
	}
	out := value.ProcessingSnapshot{RootID: root, Epoch: uid(p.Epoch), Sequence: p.Sequence, Complete: true, Nodes: []value.ProcessingNode{}, Rules: []value.ProcessingRule{}, ObservedAt: started, FreshUntil: identity.Earlier(until, p.ValidUntil.Time)}
	queue := []artifact.Location{{ArtifactID: artifactID}}
	seen := map[string]bool{}
	for len(queue) > 0 {
		loc := queue[0]
		queue = queue[1:]
		if seen[loc.ArtifactID] {
			continue
		}
		seen[loc.ArtifactID] = true
		if len(seen) > value.MaxProcessingAncestors {
			return zero, p, value.ErrUnavailable
		}
		r, e := q.ReadProcessingNode(ctx, custodydb.ReadProcessingNodeParams{RootID: id(root), ArtifactID: id(loc.ArtifactID)})
		if e != nil {
			return zero, p, value.ErrUnavailable
		}
		node := value.ProcessingNode{CaptureID: uid(r.CaptureID), Location: artifact.Location{ClusterID: uid(r.ClusterID), ArtifactID: uid(r.ArtifactID), AttemptID: uid(r.AttemptID)}, Target: authorization.Target{ClusterID: uid(r.ClusterID), NamespaceUID: r.NamespaceUid, WorkloadUID: r.WorkloadUid, PodUID: r.PodUid}, AnchorAt: r.AnchorAt.Time, DeleteBy: r.DeleteBy.Time, RetireBy: r.RetireBy.Time, Origin: r.Origin}
		if json.Unmarshal(r.Parents, &node.Parents) != nil || !node.Valid() || loc.ClusterID != "" && loc != node.Location {
			return zero, p, value.ErrUnavailable
		}
		if len(out.Nodes) == 0 {
			out.Subject = node.Location
		}
		out.Nodes = append(out.Nodes, node)
		queue = append(queue, node.Parents...)
		if len(queue) > value.MaxProcessingAncestors*value.MaxProcessingParents {
			return zero, p, value.ErrUnavailable
		}
	}
	rules, e := q.ReadProcessingRules(ctx, id(root))
	if e != nil || len(rules) > value.MaxProcessingRules {
		return zero, p, value.ErrUnavailable
	}
	for _, r := range rules {
		v := value.ProcessingRule{ID: uid(r.ID), Revision: r.Revision, State: r.State, ReleaseAcknowledged: r.State == "released", AdministrationUntil: r.ValidUntil.Time, RetireBy: r.RetireBy.Time}
		if json.Unmarshal(r.Scope, &v.Scope) != nil || !v.Valid() {
			return zero, p, value.ErrUnavailable
		}
		out.Rules = append(out.Rules, v)
	}
	last, e := q.ReadProcessingRoot(ctx, id(root))
	if e != nil || last.Sequence != p.Sequence || last.Epoch != p.Epoch || last.InitializationID != p.InitializationID || last.BackingRevision != p.BackingRevision || !bytes.Equal(last.Backing, p.Backing) {
		return zero, p, value.ErrUnavailable
	}
	n, e = q.CurrentTime(ctx)
	if e != nil || ctx.Err() != nil || !processingRootValid(last, installation, n.Time) || !out.Allows(n.Time) {
		return zero, p, value.ErrUnavailable
	}
	return out, p, nil
}
func processingProof(s value.ProcessingSnapshot, source custodydb.ProcessingRoot) artifact.DownloadProcessingProof {
	// Stable typed state excludes observation timestamps. This fingerprint is
	// neither an approval nor an authentication credential.
	b, _ := json.Marshal(struct {
		Epoch    string
		Sequence int64
		Nodes    []value.ProcessingNode
		Rules    []value.ProcessingRule
		Source   string
		Guard    []byte
		Backing  []byte
	}{s.Epoch, s.Sequence, s.Nodes, s.Rules, uid(source.SourceUid), source.ProtectionDigest, source.Backing})
	return artifact.DownloadProcessingProof{RootID: s.RootID, Epoch: s.Epoch, CaptureID: s.Nodes[0].CaptureID, Location: s.Subject, Sequence: s.Sequence, StateDigest: sha256.Sum256(b), ObservedAt: s.ObservedAt, ValidUntil: s.FreshUntil}
}
func (s *ProcessingReads) ContextProcessing(ctx context.Context, r app.ContextDownloadEvidence, recovery artifact.RecoveryProof) (artifact.DownloadProcessingProof, error) {
	var out artifact.DownloadProcessingProof
	if s == nil || ctx == nil || ctx.Err() != nil || !r.Retained.Valid() || r.Retained.RootID != s.root || !authorization.UUID(r.CaptureID) {
		return out, value.ErrUnavailable
	}
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	e := s.ledger.transaction(call, func(q *custodydb.Queries) error {
		started, e := q.CurrentTime(call)
		if e != nil {
			return e
		}
		if !identity.Fresh(r.ObservedAt, r.ValidUntil, started.Time, 5*time.Second) || !recovery.Valid(started.Time) {
			return value.ErrUnavailable
		}
		trust, e := s.recovery.lock(call, q, s.root, recovery)
		if e != nil {
			return e
		}
		until := identity.Earlier(started.Time.Add(5*time.Second), identity.Earlier(r.ValidUntil, identity.Earlier(recovery.FreshUntil, r.Retained.Effective.ExpiresAt)))
		if d, ok := call.Deadline(); ok {
			until = identity.Earlier(until, d)
		}
		snapshot, p, e := readProcessingSnapshot(call, q, s.root, s.recovery.installation, recovery.IssuerEpoch, r.Retained.Registration.Location.ArtifactID, started.Time, until)
		if e != nil {
			return e
		}
		node := snapshot.Nodes[0]
		if node.CaptureID != r.CaptureID || node.Location != r.Retained.Registration.Location || node.Target != r.Retained.Input.Target || !node.AnchorAt.Equal(r.Retained.Registration.AnchorAt) || !node.DeleteBy.Equal(r.Retained.Registration.DeleteBy) {
			return value.ErrUnavailable
		}
		if e = s.recovery.check(call, q, trust, s.root, recovery); e != nil {
			return e
		}
		out = processingProof(snapshot, p)
		now, e := q.CurrentTime(call)
		if e != nil || !out.Valid(now.Time) {
			return value.ErrUnavailable
		}
		return call.Err()
	})
	if e != nil || call.Err() != nil {
		return artifact.DownloadProcessingProof{}, value.ErrUnavailable
	}
	return out, nil
}

// Caller owns recovery then the permission root lock. Every processing mutation
// takes the same root, so no contrary rule can commit during this effect.
func processingDownloadFence(ctx context.Context, q *custodydb.Queries, a artifact.DownloadAuthority) error {
	now, e := q.CurrentTime(ctx)
	if e != nil || !a.Environment.CurrentValid(now.Time) || a.Environment.Processing.CaptureID != a.Scope.CaptureID {
		return value.ErrUnavailable
	}
	expected := a.Environment.Processing
	snapshot, p, e := readProcessingSnapshot(ctx, q, a.Scope.RootID, a.Environment.InstallationID, a.Environment.RecoveryEpoch, a.Scope.ArtifactID, expected.ObservedAt, expected.ValidUntil)
	if e != nil {
		return e
	}
	observed := processingProof(snapshot, p)
	if observed.RootID != expected.RootID || observed.Epoch != expected.Epoch || observed.Sequence != expected.Sequence || observed.CaptureID != expected.CaptureID || observed.Location != expected.Location || observed.StateDigest != expected.StateDigest {
		return value.ErrUnavailable
	}
	final, e := q.CurrentTime(ctx)
	if e != nil || !a.Valid(final.Time) || !expected.Valid(final.Time) || ctx.Err() != nil {
		return value.ErrUnavailable
	}
	return nil
}
