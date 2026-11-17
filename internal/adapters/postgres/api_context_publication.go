package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

func validCompletedAPI(r value.APIExecution, e artifact.ContextExpectation) bool {
	return r.Valid() && r.Phase == "stored" && r.Binding.CaptureID == e.CaptureUID && r.Binding.AttemptID == e.Registration.Location.AttemptID && r.Binding.ClusterID == e.Registration.Location.ClusterID && r.Binding.PodUID == e.PodUID && r.Binding.ScopeDigest == e.PlanDigest && r.ExpectationDigest == evidence.ContextExpectationDigest(e) && r.Copies.Validate(e.Registration) == nil && r.CompletedAt.Before(e.Registration.WriteUntil)
}

// A completed execution retains the admitted digest; semantic verification
// binds the independently projected completion expectation instead.
func validCompletedAPICapture(r value.APIExecution, e artifact.ContextExpectation, c custodydb.ContextCapture) bool {
	accepted, err := admittedRecord(c)
	if err != nil || !validCompletedAPI(r, accepted.Expectation) {
		return false
	}
	projected, err := storedSnapshotProjection(accepted.Expectation, c.SnapshotCoverage, c.SnapshotCoverageDigest, c.SnapshotExpectationDigest)
	return err == nil && (e.Snapshot == nil || len(c.SnapshotCoverage) > 0) && evidence.ContextExpectationDigest(projected) == evidence.ContextExpectationDigest(e)
}

func currentVerificationRecord(ctx context.Context, q *custodydb.Queries, c custodydb.ContextCapture, v custodydb.ContextVerification) (audit.ContextVerification, error) {
	e, err := acceptedPublication(c)
	if err != nil {
		return audit.ContextVerification{}, err
	}
	if e.ExecutionClass != artifact.ContextAPIExecution {
		return verificationRecord(c, v)
	}
	row, err := q.ReadAPIExecution(ctx, custodydb.ReadAPIExecutionParams{RootID: c.RootID, CaptureID: c.ID})
	if err != nil {
		return audit.ContextVerification{}, err
	}
	r, err := apiExecution(row)
	if err != nil {
		return audit.ContextVerification{}, err
	}
	return verificationRecord(c, v, r)
}

// APIContextPublicationGate uses completed acquisition history plus current SQL
// permission and retained policy fences. It has no collector or live
// target reader, and cannot start or repeat a missing acquisition.
type APIContextPublicationGate struct {
	publications *ContextPublications
}

func NewAPIContextPublicationGate(ctx context.Context, pool *pgxpool.Pool, root string) (*APIContextPublicationGate, error) {
	p, err := NewContextPublications(ctx, pool, root)
	if err != nil {
		return nil, err
	}
	return &APIContextPublicationGate{p}, nil
}
func (s *APIContextPublicationGate) CheckContextPublication(ctx context.Context, e artifact.ContextExpectation) (artifact.PublicationAuthority, error) {
	var out artifact.PublicationAuthority
	if s == nil || e.Validate() != nil || e.ExecutionClass != artifact.ContextAPIExecution {
		return out, artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := s.publications.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = artifact.PublicationAuthority{}
		stream, err := q.LockPermissionStream(ctx, id(s.publications.root))
		if err != nil {
			return err
		}
		row, err := q.ReadAPIExecutionPublication(ctx, custodydb.ReadAPIExecutionPublicationParams{RootID: id(s.publications.root), CaptureID: id(e.CaptureUID)})
		if err != nil {
			return privacyapp.ErrFence
		}
		r, err := apiExecution(row.ContextExecution)
		if err != nil || !validCompletedAPICapture(r, e, row.ContextCapture) {
			return privacyapp.ErrFence
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		until := now.Time.Add(5 * time.Second)
		for _, end := range []time.Time{stream.FreshUntil.Time, stream.LeaseUntil.Time, e.Registration.WriteUntil, e.Registration.ExpiresAt} {
			until = identity.Earlier(until, end)
		}
		if deadline, ok := ctx.Deadline(); ok {
			until = identity.Earlier(until, deadline)
		}
		out = artifact.PublicationAuthority{RootID: s.publications.root, CaptureID: e.CaptureUID, PermissionEpoch: uid(stream.Epoch), PermissionSequence: stream.Sequence, ExpectationDigest: evidence.ContextExpectationDigest(e), AuthorityDigest: executionapp.APIExecutionDigest(r), CheckedAt: now.Time, ValidUntil: until}
		copy(out.ProjectionDigest[:], stream.ProjectionDigest)
		if err = s.publications.publicationFence(ctx, q, stream, e, out); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return artifact.PublicationAuthority{}, err
	}
	return out, nil
}

var _ evidence.ContextPublicationGate = (*APIContextPublicationGate)(nil)
