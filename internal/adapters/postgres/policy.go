package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	authapp "asservat.local/asservat/internal/application/authorization"
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Role-specific credentials provide the actual SQL boundary. Source writers,
// acceptors, audit publishers and readers are composed separately.
type Policies struct {
	ledger             *Ledger
	root, installation string
	recovery           *RecoveryTransactionGuard
}

var _ app.PolicySourceWriter = (*Policies)(nil)
var _ app.PolicyAcceptor = (*Policies)(nil)
var _ authapp.AcceptedPolicyReader = (*Policies)(nil)
var _ app.PolicyGrantAcceptanceReader = (*Policies)(nil)

func NewPolicies(ctx context.Context, pool *pgxpool.Pool, root, installation string) (*Policies, error) {
	guard, err := NewRecoveryTransactionGuard(root, installation)
	if err != nil {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return &Policies{l, root, installation, guard}, nil
}
func policySource(row custodydb.PolicySource) value.PolicySource {
	s := value.PolicySource{InstallationID: uid(row.InstallationID), ClusterID: uid(row.ClusterID), NamespaceUID: row.NamespaceUid, Name: row.Name, Revision: identity.Revision{UID: row.PolicyUid, Generation: row.Generation}, ResourceVersion: row.ResourceVersion, ObservedAt: row.ObservedAt.Time.UTC(), FreshUntil: row.FreshUntil.Time.UTC(), Deleted: row.Deleted, Suspended: row.Suspended}
	copy(s.Revision.Digest[:], row.SpecDigest)
	copy(s.CollectionDigest[:], row.CollectionDigest)
	return s
}
func samePolicySourceIdentity(a, b value.PolicySource) bool {
	return a.InstallationID == b.InstallationID && a.ClusterID == b.ClusterID && a.NamespaceUID == b.NamespaceUID && a.Name == b.Name && a.Revision.UID == b.Revision.UID
}
func (s *Policies) ObservePolicy(ctx context.Context, in value.PolicySource) error {
	in.ObservedAt = in.ObservedAt.UTC()
	in.FreshUntil = in.FreshUntil.UTC()
	if in.InstallationID != s.installation || !in.Valid(in.ObservedAt) || in.ObservedAt.Nanosecond()%1000 != 0 || in.FreshUntil.Nanosecond()%1000 != 0 {
		return value.ErrInvalid
	}
	return captureError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		// Root first serializes first inserts and prevents accepting against a source
		// update in flight. Observations cannot acknowledge or alter accepted records.
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !in.Valid(now.Time) {
			return value.ErrChanged
		}
		err = q.InsertPolicySource(ctx, custodydb.InsertPolicySourceParams{RootID: id(s.root), PolicyUid: in.Revision.UID, InstallationID: id(s.installation), ClusterID: id(in.ClusterID), NamespaceUid: in.NamespaceUID, Name: in.Name, Generation: in.Revision.Generation, SpecDigest: in.Revision.Digest[:], ResourceVersion: in.ResourceVersion, ObservedAt: ts(in.ObservedAt), FreshUntil: ts(in.FreshUntil), Deleted: in.Deleted, Suspended: in.Suspended, CollectionDigest: in.CollectionDigest[:]})
		if err != nil {
			return err
		}
		row, err := q.LockPolicySource(ctx, custodydb.LockPolicySourceParams{RootID: id(s.root), PolicyUid: in.Revision.UID})
		if err != nil {
			return err
		}
		old := policySource(row)
		if !samePolicySourceIdentity(old, in) || old.Deleted && !in.Deleted || in.Revision.Generation < old.Revision.Generation || in.Revision.Generation == old.Revision.Generation && (in.Revision.Digest != old.Revision.Digest || in.CollectionDigest != old.CollectionDigest || in.Suspended != old.Suspended) || in.ObservedAt.Before(old.ObservedAt) {
			return value.ErrChanged
		}
		if in.ObservedAt.Equal(old.ObservedAt) {
			if in != old {
				return value.ErrChanged
			}
		} else if err = q.UpdatePolicySource(ctx, custodydb.UpdatePolicySourceParams{RootID: id(s.root), PolicyUid: in.Revision.UID, Generation: in.Revision.Generation, SpecDigest: in.Revision.Digest[:], ResourceVersion: in.ResourceVersion, ObservedAt: ts(in.ObservedAt), FreshUntil: ts(in.FreshUntil), Deleted: in.Deleted, Suspended: in.Suspended, CollectionDigest: in.CollectionDigest[:]}); err != nil {
			return err
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !in.Valid(now.Time) {
			return value.ErrChanged
		}
		return nil
	}))
}

// Request digest excludes refreshable identity/recovery proofs. Exact ambiguous
// retries return the first immutable receipt and never renew scope or spending.
func policyRequestDigest(a value.PolicyAdmission) []byte {
	return digest(struct {
		Submission value.VerifiedPolicySubmission
		Authority  authorization.AcceptedPolicyAuthority
	}{a.Submission, a.Authority})
}
func decodePolicy(row custodydb.PolicyAcceptance) (value.PolicyAcceptance, error) {
	var out value.PolicyAcceptance
	if len(row.Record) == 0 || len(row.Record) > 64<<10 {
		return out, value.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(row.Record))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || !out.Valid() || out.ID != uid(row.ID) || out.RootID != uid(row.RootID) || out.Authority.PolicyUID != row.PolicyUid || out.Source.Revision.Generation != row.Generation || out.Submission.Nonce != uid(row.Nonce) || !out.AcceptedAt.Equal(row.AcceptedAt.Time) || !bytes.Equal(out.Authority.ScopeDigest[:], row.ScopeDigest) || !bytes.Equal(digest(out), row.RecordDigest) || !bytes.Equal(policyRequestDigest(value.PolicyAdmission{Submission: out.Submission, Authority: out.Authority}), row.RequestDigest) {
		return value.PolicyAcceptance{}, value.ErrUnavailable
	}
	return out, nil
}
func (s *Policies) AcceptPolicy(ctx context.Context, in value.PolicyAdmission) (value.AcceptedPolicy, error) {
	var out value.AcceptedPolicy
	if in.RootID != s.root || in.Authority.InstallationID != s.installation || !in.Submission.Valid(in.Submission.IssuedAt) {
		return out, value.ErrInvalid
	}
	request := policyRequestDigest(in)
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, err := s.recovery.lock(ctx, q, s.root, in.Recovery)
		if err != nil {
			return err
		}
		stream, err := q.LockPermissionStream(ctx, id(s.root))
		if err != nil {
			return err
		}
		prior, err := q.FindPolicyNonce(ctx, custodydb.FindPolicyNonceParams{RootID: id(s.root), Nonce: id(in.Submission.Nonce)})
		if err == nil {
			if !bytes.Equal(prior.RequestDigest, request) {
				return value.ErrConflict
			}
			record, err := decodePolicy(prior)
			if err != nil {
				return err
			}
			out = value.AcceptedPolicy{Record: record, Replay: true}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		row, err := q.LockPolicySource(ctx, custodydb.LockPolicySourceParams{RootID: id(s.root), PolicyUid: in.Authority.PolicyUID})
		if err != nil {
			return err
		}
		source := policySource(row)
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !in.Valid(now.Time) || !source.Valid(now.Time) || source.Deleted || source.Suspended || source.InstallationID != s.installation || source.Revision != in.Submission.Source || source.ClusterID != in.Submission.ClusterID || source.NamespaceUID != in.Submission.NamespaceUID || source.Name != in.Submission.Name {
			return value.ErrDenied
		}
		if (!row.ActiveID.Valid && in.Submission.ReplacesID != "") || (row.ActiveID.Valid && uid(row.ActiveID) != in.Submission.ReplacesID) {
			return value.ErrConflict
		}
		if _, err = q.FindPolicyScope(ctx, custodydb.FindPolicyScopeParams{RootID: id(s.root), PolicyUid: source.Revision.UID, ScopeDigest: in.Authority.ScopeDigest[:]}); err == nil {
			return value.ErrConflict
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}

		var creator identity.Principal
		if len(row.CreatorJson) == 0 {
			if in.Authority.Creator != in.Author.Principal {
				return value.ErrDenied
			}
		} else if json.Unmarshal(row.CreatorJson, &creator) != nil || creator != in.Authority.Creator {
			return value.ErrDenied
		}
		var current authorization.AutomationProjection
		if in.Workload != nil {
			target := authorization.Target{ClusterID: in.Workload.ClusterID, NamespaceUID: in.Workload.NamespaceUID, WorkloadUID: in.Workload.WorkloadUID}
			current, err = automationProjectionFor(ctx, q, stream, s.installation, in.Authority.Delegation, target, nil)
		} else {
			current, err = automationProjection(ctx, q, stream, s.installation, in.Authority, in.Target)
		}
		if err != nil {
			return err
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		use := authorization.PolicyUse{PolicyUID: in.Authority.PolicyUID, ScopeDigest: in.Authority.ScopeDigest, Target: in.Target, Purpose: authorization.PolicyIncident}
		eligibility := authorization.ValidatePolicyAcceptance(in.Author, in.Authority, current, use, now.Time)
		var workloadScope authorization.WorkloadAutomationProjection
		if in.Workload != nil {
			p := current.Permissions
			workloadScope = authorization.WorkloadAutomationProjection{InstallationID: current.InstallationID, Delegation: current.Delegation, Envelope: current.Envelope, ObservedAt: current.ObservedAt, FreshUntil: current.FreshUntil, NotAfter: current.NotAfter, Disabled: current.Disabled, Permissions: authorization.WorkloadProjection{Target: *in.Workload, Revision: p.Revision, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil, DeniesComplete: p.DeniesComplete, DeniesObservedAt: p.DeniesObservedAt, DeniesFreshUntil: p.DeniesFreshUntil, Allows: p.Allows, Denies: p.Denies}}
			eligibility = authorization.ValidatePolicyWorkloadAcceptance(in.Author, in.Authority, workloadScope, now.Time)
		}
		if !eligibility.Eligible {
			return value.ErrDenied
		}
		// ADR-239: a sharing instruction's management must still be exactly the
		// activating human's evidence-owner teams of this delegation, on the
		// projection evaluated after these locks.
		if in.Sharing != nil {
			var sponsors []string
			for _, o := range in.Authority.Owners {
				sponsors = append(sponsors, o.SubjectID)
			}
			result, management := authorization.PolicyShareManagement(in.Author, current.Permissions, in.Target, in.Authority.Delegation.UID, sponsors, now.Time)
			if in.Workload != nil {
				result, management = authorization.PolicyWorkloadShareManagement(in.Author, workloadScope.Permissions, *in.Workload, in.Authority.Delegation.UID, sponsors, now.Time)
			}
			if !result.Eligible || !slices.Equal(management, in.Sharing.Management) || !in.Sharing.NotAfter.After(now.Time) {
				return value.ErrSharingDenied
			}
		}
		event, err := q.NewPolicyAcceptanceID(ctx)
		if err != nil {
			return err
		}
		record := value.PolicyAcceptance{ID: uid(event), RootID: s.root, Source: source, Submission: in.Submission, Authority: in.Authority, Submitter: in.Author.Principal, IdentityRevision: in.Author.Policy, PermissionRevision: current.Permissions.Revision, Recovery: in.Recovery, AcceptedAt: now.Time, IntentVersion: row.IntentVersion, Sharing: in.Sharing}
		if !record.Valid() {
			return value.ErrInvalid
		}
		encoded, err := json.Marshal(record)
		if err != nil || len(encoded) > 64<<10 {
			return value.ErrInvalid
		}
		creatorJSON, err := json.Marshal(in.Authority.Creator)
		if err != nil {
			return err
		}
		n, err := q.ActivatePolicyAcceptance(ctx, custodydb.ActivatePolicyAcceptanceParams{RootID: id(s.root), PolicyUid: source.Revision.UID, CreatorJson: creatorJSON, ActiveID: event})
		if err != nil {
			return err
		}
		if n != 1 {
			return value.ErrChanged
		}

		_, err = q.InsertPolicyAcceptance(ctx, custodydb.InsertPolicyAcceptanceParams{ID: event, RootID: id(s.root), PolicyUid: source.Revision.UID, Generation: source.Revision.Generation, Nonce: id(in.Submission.Nonce), RequestDigest: request, RecordDigest: digest(record), Record: encoded, AcceptedAt: ts(record.AcceptedAt), ScopeDigest: record.Authority.ScopeDigest[:]})
		if err != nil {
			return err
		}
		if err = s.recovery.check(ctx, q, trust, s.root, in.Recovery); err != nil {
			return err
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if now.Time.Before(record.AcceptedAt) || !in.Valid(now.Time) || !source.Valid(now.Time) || !now.Time.Before(eligibility.ValidUntil) {
			return value.ErrChanged
		}
		out = value.AcceptedPolicy{Record: record}
		return nil
	})
	if err != nil {
		return value.AcceptedPolicy{}, captureError(err)
	}
	return out, nil
}

func (s *Policies) AcceptedPolicyAuthority(ctx context.Context, policy string) (authorization.AcceptedPolicySnapshot, error) {
	out, _, err := s.AcceptedPolicyRecord(ctx, policy)
	return out, err
}

// AcceptedPolicyRecord returns the same current, independently audited team
// authority with its immutable source provenance for server-side grant planning.
// It reuses the existing accepted read transaction and role, not a new lookup.
func (s *Policies) AcceptedPolicyRecord(ctx context.Context, policy string) (authorization.AcceptedPolicySnapshot, value.PolicyAcceptance, error) {
	var out authorization.AcceptedPolicySnapshot
	var record value.PolicyAcceptance
	if !identity.Text(policy, 64) {
		return out, record, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		// A restored database never makes accepted authority available until the
		// current recovery producer has re-established installation trust.
		trust, err := q.ShareFleetTrust(ctx, id(s.installation))
		if err != nil {
			return err
		}
		if _, err = q.SharePermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		row, err := q.SharePolicySource(ctx, custodydb.SharePolicySourceParams{RootID: id(s.root), PolicyUid: policy})
		if err != nil {
			return err
		}
		out, record, err = acceptedPolicyIn(ctx, q, s.root, s.installation, trust, row)
		return err
	})
	if err != nil {
		return authorization.AcceptedPolicySnapshot{}, value.PolicyAcceptance{}, captureError(err)
	}
	return out, record, nil
}

// acceptedPolicyIn checks the current acknowledged acceptance of one policy
// source row inside the caller's transaction, which already holds the
// recovery and permission-root locks (or shares them). The snapshot's
// FreshUntil is the original source/recovery bound, never renewed here.
func acceptedPolicyIn(ctx context.Context, q *custodydb.Queries, root, installation string, trust custodydb.FleetCurrentTrust, row custodydb.PolicySource) (authorization.AcceptedPolicySnapshot, value.PolicyAcceptance, error) {
	var zero authorization.AcceptedPolicySnapshot
	source := policySource(row)
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return zero, value.PolicyAcceptance{}, err
	}
	if source.InstallationID != installation || source.Deleted || source.Suspended || !source.Valid(now.Time) || !row.ActiveID.Valid {
		return zero, value.PolicyAcceptance{}, value.ErrUnavailable
	}
	started := now.Time
	accepted, err := q.ReadPolicyAcceptance(ctx, custodydb.ReadPolicyAcceptanceParams{RootID: id(root), ID: row.ActiveID})
	if err != nil {
		return zero, value.PolicyAcceptance{}, err
	}
	r, err := decodePolicy(accepted)
	if err != nil {
		return zero, value.PolicyAcceptance{}, err
	}
	var receipt audit.Receipt
	if !accepted.AcknowledgedAt.Valid || json.Unmarshal(accepted.ReceiptJson, &receipt) != nil || !receipt.ValidPolicyAcceptance(root, r.ID) || (r.IntentVersion != row.IntentVersion || r.Source.CollectionDigest != source.CollectionDigest) || !samePolicySourceIdentity(r.Source, source) || r.Recovery.IssuerEpoch != uid(trust.IssuerEpoch) {
		return zero, value.PolicyAcceptance{}, value.ErrUnavailable
	}
	now, err = q.CurrentTime(ctx)
	if err != nil {
		return zero, value.PolicyAcceptance{}, err
	}
	recovery, err := recoveryState(trust, now.Time, now.Time)
	if err != nil {
		return zero, value.PolicyAcceptance{}, err
	}
	until := identity.Earlier(source.FreshUntil, identity.Earlier(recovery.FreshUntil, r.Authority.NotAfter))
	if now.Time.Before(started) || !source.Valid(now.Time) || !r.Authority.Valid(now.Time) || !now.Time.Before(until) {
		return zero, value.PolicyAcceptance{}, value.ErrUnavailable
	}
	return authorization.AcceptedPolicySnapshot{IntentVersion: r.IntentVersion, SourceRevision: r.Source.Revision, Authority: r.Authority, ObservedAt: source.ObservedAt, FreshUntil: until, SourceUntil: identity.Earlier(source.FreshUntil, r.Authority.NotAfter)}, r, nil
}
