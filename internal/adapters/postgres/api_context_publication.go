package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	privacyvalue "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

func validCompletedAPI(r value.APIExecution, e artifact.ContextExpectation) bool {
	return r.Valid() && r.Phase == "stored" && r.Binding.CaptureID == e.CaptureUID && r.Binding.AttemptID == e.Registration.Location.AttemptID && r.Binding.ClusterID == e.Registration.Location.ClusterID && r.Binding.PodUID == e.PodUID && r.Binding.ScopeDigest == e.PlanDigest && r.ExpectationDigest == evidence.ContextExpectationDigest(e) && r.Process.ImageDigest == e.CollectorImageDigest && r.Copies.Validate(e.Registration) == nil && r.CompletedAt.Before(e.Registration.WriteUntil)
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
// permission, recovery and retained policy fences. It has no collector or live
// target reader, and cannot start or repeat a missing acquisition.
type APIContextPublicationGate struct {
	publications *ContextPublications
	retention    privacyapp.RetentionResolver
	recovery     fleetapp.RecoveryReader
}

func NewAPIContextPublicationGate(ctx context.Context, pool *pgxpool.Pool, root string, guards EffectTransactionGuards, retention privacyapp.RetentionResolver, recovery fleetapp.RecoveryReader) (*APIContextPublicationGate, error) {
	if retention.RetainedPolicies == nil || retention.Now == nil || recovery == nil {
		return nil, artifact.ErrInvalid
	}
	p, err := NewContextPublications(ctx, pool, root, guards)
	if err != nil {
		return nil, err
	}
	return &APIContextPublicationGate{p, retention, recovery}, nil
}
func (s *APIContextPublicationGate) CheckContextPublication(ctx context.Context, e artifact.ContextExpectation) (artifact.PublicationAuthority, error) {
	var out artifact.PublicationAuthority
	if s == nil || e.Validate() != nil || e.ExecutionClass != artifact.ContextAPIExecution {
		return out, artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	target := authorization.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}
	d := privacyvalue.Deadlines{AnchorAt: e.Registration.AnchorAt, ExpiresAt: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy}
	retained, err := s.retention.ResolveRetained(ctx, privacyvalue.Input{Target: target, PrivacyClass: "potentialPersonalData", EvidenceType: e.Type().EvidenceType, RequestedSeconds: e.RequestedAgeSeconds, AnchorAt: d.AnchorAt}, d, e.RetentionRules)
	if err != nil {
		return out, err
	}
	recovery, err := s.recovery.RecoveryState(ctx)
	if err != nil {
		return out, err
	}
	topology, err := s.publications.retention.observe(ctx, target.ClusterID)
	if err != nil {
		return out, err
	}
	err = s.publications.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = artifact.PublicationAuthority{}
		trust, err := s.publications.recovery.lock(ctx, q, s.publications.root, recovery)
		if err != nil {
			return err
		}
		stream, err := q.LockPermissionStream(ctx, id(s.publications.root))
		if err != nil {
			return err
		}
		row, err := q.ReadAPIExecution(ctx, custodydb.ReadAPIExecutionParams{RootID: id(s.publications.root), CaptureID: id(e.CaptureUID)})
		if err != nil {
			return privacyapp.ErrFence
		}
		r, err := apiExecution(row)
		if err != nil || !validCompletedAPI(r, e) {
			return privacyapp.ErrFence
		}
		// The original protected process/issuer must match the installation for which
		// this completed result was admitted; restoration cannot revive old effects.
		if r.Process.InstallationID != recovery.InstallationID || r.Process.IssuerEpoch != recovery.IssuerEpoch {
			return privacyapp.ErrFence
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		until := identity.Earlier(now.Time.Add(5*time.Second), retained.ValidUntil)
		for _, end := range []time.Time{recovery.FreshUntil, stream.FreshUntil.Time, stream.LeaseUntil.Time, e.Registration.WriteUntil, retained.ExpiresAt} {
			until = identity.Earlier(until, end)
		}
		if deadline, ok := ctx.Deadline(); ok {
			until = identity.Earlier(until, deadline)
		}
		out = artifact.PublicationAuthority{RootID: s.publications.root, CaptureID: e.CaptureUID, PermissionEpoch: uid(stream.Epoch), PermissionSequence: stream.Sequence, ExpectationDigest: evidence.ContextExpectationDigest(e), AuthorityDigest: executionapp.APIExecutionDigest(r), CheckedAt: now.Time, ValidUntil: until, Retention: retained.Proof, Recovery: recovery}
		copy(out.ProjectionDigest[:], stream.ProjectionDigest)
		if err = s.publications.publicationFence(ctx, q, stream, e, out, topology, trust); err != nil {
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
