package postgres

import (
	"bytes"
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ClusterCredentials applies ADR-168 decisions under one lineage row lock and
// the database clock. It stores public keys only and grants no authority: an
// accepted presentation still needs the full ADR-126/153 admission.
type ClusterCredentials struct {
	ledger *Ledger
	root   string
}

func NewClusterCredentials(ctx context.Context, pool *pgxpool.Pool, root string) (*ClusterCredentials, error) {
	if !authorization.UUID(root) {
		return nil, fleet.ErrClusterCredentialDenied
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &ClusterCredentials{ledger: l, root: root}, nil
}

// Generation 1 arises only from an activated fleet operator bootstrap
// (ADR-193, ClusterBootstraps); this store never writes a lineage.

var _ fleetapp.ClusterCredentialStore = (*ClusterCredentials)(nil)

// Decide runs the caller's decision under the lineage row lock with the
// database clock and persists it. A fork commits the permanent fence before
// returning an error. No signature or key material is interpreted here.
func (s *ClusterCredentials) Decide(ctx context.Context, r fleet.ClusterCredentialRequest, decide fleetapp.ClusterCredentialDecider) (fleet.ClusterCredentialPresentation, error) {
	var out fleet.ClusterCredentialPresentation
	if s == nil || decide == nil || !r.Valid() || r.Profile.RootID != s.root {
		return out, fleet.ErrClusterCredentialDenied
	}
	var decision fleet.ClusterDecision
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out, decision = fleet.ClusterCredentialPresentation{}, fleet.ClusterDecision{}
		row, err := q.LockClusterEnrollmentLineage(ctx, custodydb.LockClusterEnrollmentLineageParams{RootID: id(r.Profile.RootID), PeerID: id(r.Profile.PeerID)})
		if err != nil {
			return fleet.ErrClusterCredentialDenied
		}
		lineage := fleet.ClusterCredentialLineage{Profile: fleet.ClusterCredentialProfile{RootID: uid(row.RootID), PeerID: uid(row.PeerID), InstallationID: uid(row.InstallationID), ClusterID: uid(row.ClusterID)}, ID: uid(row.LineageID), Policy: fleet.ClusterCredentialPolicy{Validity: time.Duration(row.ValiditySeconds) * time.Second, Rotation: time.Duration(row.RotationSeconds) * time.Second}, Current: row.CurrentGeneration, Fenced: row.Fenced.String}
		current, err := clusterCredential(q, ctx, row.LineageID, row.CurrentGeneration)
		if err != nil {
			return err
		}
		signer, err := clusterCredential(q, ctx, row.LineageID, r.Generation)
		if err != nil {
			signer = nil // unknown generation: the decision denies without state change
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		decision, err = decide(lineage, signer, current, now.Time)
		if err != nil {
			return err
		}
		generation := current.Generation
		switch decision.Kind {
		case fleet.ClusterAccept:
			if decision.FirstUse {
				if n, e := q.MarkClusterEnrollmentFirstUse(ctx, custodydb.MarkClusterEnrollmentFirstUseParams{LineageID: row.LineageID, Generation: current.Generation, FirstUsedAt: ts(now.Time)}); e != nil || n != 1 {
					return fleet.ErrClusterCredentialDenied
				}
			}
		case fleet.ClusterRotate:
			old, next := decision.Supersede, decision.Next
			if n, e := q.SupersedeClusterEnrollmentCredential(ctx, custodydb.SupersedeClusterEnrollmentCredentialParams{LineageID: row.LineageID, Generation: old.Generation, SupersededAt: ts(old.SupersededAt), SuccessorDigest: old.Successor[:]}); e != nil || n != 1 {
				return fleet.ErrClusterCredentialDenied
			}
			if e := q.InsertClusterEnrollmentCredential(ctx, custodydb.InsertClusterEnrollmentCredentialParams{LineageID: row.LineageID, Generation: next.Generation, PublicKey: next.PublicKey, IssuedAt: ts(next.IssuedAt), ValidUntil: ts(next.ValidUntil)}); e != nil {
				return e
			}
			if n, e := q.AdvanceClusterEnrollmentLineage(ctx, custodydb.AdvanceClusterEnrollmentLineageParams{LineageID: row.LineageID, CurrentGeneration: old.Generation}); e != nil || n != 1 {
				return fleet.ErrClusterCredentialDenied
			}
			generation, current = next.Generation, next
		case fleet.ClusterReplay:
		case fleet.ClusterFork:
			n, e := q.FenceClusterEnrollmentLineage(ctx, custodydb.FenceClusterEnrollmentLineageParams{LineageID: row.LineageID, Fenced: pgtype.Text{String: "fork", Valid: true}, FencedAt: ts(now.Time)})
			if e != nil || n != 1 {
				return fleet.ErrClusterCredentialDenied
			}
			return nil // commit the fence; the caller still receives a denial
		default:
			return fleet.ErrClusterCredentialDenied
		}
		out = fleet.ClusterCredentialPresentation{Profile: lineage.Profile, LineageID: lineage.ID, Operation: r.Operation, Generation: generation, CheckedAt: now.Time, ValidUntil: identity.Earlier(now.Time.Add(5*time.Second), current.ValidUntil)}
		return nil
	})
	if err != nil {
		for _, sentinel := range []error{fleet.ErrClusterCredentialFenced, fleet.ErrClusterCredentialDenied} {
			if errors.Is(err, sentinel) {
				return fleet.ClusterCredentialPresentation{}, sentinel
			}
		}
		return fleet.ClusterCredentialPresentation{}, err
	}
	if decision.Kind == fleet.ClusterFork {
		return fleet.ClusterCredentialPresentation{}, fleet.ErrClusterCredentialFenced
	}
	return out, nil
}

// Revoke permanently fences the profile's current lineage. Rotation cannot
// undo it; only administrator reenrollment installs a new lineage.
func (s *ClusterCredentials) Revoke(ctx context.Context, p fleet.ClusterCredentialProfile) error {
	if s == nil || !p.Valid() || p.RootID != s.root {
		return fleet.ErrClusterCredentialDenied
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.LockClusterEnrollmentLineage(ctx, custodydb.LockClusterEnrollmentLineageParams{RootID: id(p.RootID), PeerID: id(p.PeerID)})
		if err != nil || uid(row.InstallationID) != p.InstallationID || uid(row.ClusterID) != p.ClusterID {
			return fleet.ErrClusterCredentialDenied
		}
		if row.Fenced.Valid {
			return nil // already fenced (fork or revoked); both deny equally
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		n, err := q.FenceClusterEnrollmentLineage(ctx, custodydb.FenceClusterEnrollmentLineageParams{LineageID: row.LineageID, Fenced: pgtype.Text{String: "revoked", Valid: true}, FencedAt: ts(now.Time)})
		if err != nil || n != 1 {
			return fleet.ErrClusterCredentialDenied
		}
		return nil
	})
}

func clusterCredential(q *custodydb.Queries, ctx context.Context, lineage pgtype.UUID, generation int64) (*fleet.ClusterCredential, error) {
	row, err := q.ReadClusterEnrollmentCredential(ctx, custodydb.ReadClusterEnrollmentCredentialParams{LineageID: lineage, Generation: generation})
	if err != nil {
		return nil, fleet.ErrClusterCredentialDenied
	}
	c := fleet.ClusterCredential{Generation: row.Generation, PublicKey: bytes.Clone(row.PublicKey), IssuedAt: row.IssuedAt.Time, ValidUntil: row.ValidUntil.Time, SupersededAt: row.SupersededAt.Time, FirstUsed: row.FirstUsedAt.Time}
	copy(c.Successor[:], row.SuccessorDigest)
	return &c, nil
}
