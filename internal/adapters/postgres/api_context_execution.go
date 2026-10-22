package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/execution"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	privacyvalue "asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// APIContextExecutions supplies three typed facets from one installed credential
// and pool. It has no key-unwrapping, capture-admission or publication rights.
type APIContextExecutions struct {
	ledger *Ledger
	root   string
	guards EffectTransactionGuards
}

func NewAPIContextExecutions(ctx context.Context, pool *pgxpool.Pool, root string, guards EffectTransactionGuards) (*APIContextExecutions, error) {
	if !authorization.UUID(root) {
		return nil, value.ErrInvalid
	}
	g, err := effectGuardsFor(root, []EffectTransactionGuards{guards})
	if err != nil {
		return nil, err
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &APIContextExecutions{l, root, g}, nil
}
func apiWork(c custodydb.ContextCapture) (app.APIContextWork, error) {
	var out app.APIContextWork
	e, err := acceptedPublication(c)
	if err != nil || e.ExecutionClass != artifact.ContextAPIExecution {
		return out, value.ErrDenied
	}
	accepted, err := admittedRecord(c)
	if err != nil {
		return out, err
	}
	intent, err := captureIntent(c)
	if err != nil {
		return out, err
	}
	var scope struct {
		Collection struct {
			Spec struct {
				Target struct {
					Namespace string                           `json:"namespace"`
					Workload  struct{ Kind, Name, UID string } `json:"workloadRef"`
				} `json:"target"`
			} `json:"spec"`
		} `json:"collection"`
	}
	if json.Unmarshal(c.ScopeJson, &scope) != nil {
		return out, value.ErrUnavailable
	}
	t := scope.Collection.Spec.Target
	request := targets.Request{ClusterID: e.Registration.Location.ClusterID, Namespace: configuration.NamespaceRef{Name: t.Namespace, UID: e.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: t.Workload.Kind, Name: t.Workload.Name, UID: t.Workload.UID}, PodName: accepted.Pin.Name, PodUID: e.PodUID}
	if !request.Valid() || request.Workload.UID != e.WorkloadUID || request.Namespace.Name != e.Namespace || accepted.Pin.NodeName != "" {
		return out, value.ErrUnavailable
	}
	out = app.APIContextWork{Accepted: accepted, Target: request, Actor: intent.Actor}
	copy(out.IntentDigest[:], c.IntentDigest)
	return out, nil
}
func apiExecution(row custodydb.ContextExecution) (value.APIExecution, error) {
	var r value.APIExecution
	if json.Unmarshal(row.BindingJson, &r.Binding) != nil || json.Unmarshal(row.ProcessJson, &r.Process) != nil || len(row.ExpectationDigest) != 32 {
		return r, value.ErrUnavailable
	}
	r.RootID = uid(row.RootID)
	r.WriterProtocol = row.WriterProtocol.String
	r.ObjectUID = uid(row.ObjectUid)
	r.Phase = row.Phase
	if !row.ObjectUid.Valid {
		r.ObjectUID = ""
	}
	copy(r.ExpectationDigest[:], row.ExpectationDigest)
	if row.StartedAt.Valid {
		r.StartedAt = row.StartedAt.Time.UTC()
	}
	if row.AcquiredAt.Valid {
		r.AcquiredAt = row.AcquiredAt.Time.UTC()
	}
	if row.CompletedAt.Valid {
		r.CompletedAt = row.CompletedAt.Time.UTC()
	}
	if len(row.CopiesJson) > 0 {
		if json.Unmarshal(row.CopiesJson, &r.Copies) != nil || !bytes.Equal(row.CopiesDigest, digest(r.Copies)) {
			return value.APIExecution{}, value.ErrUnavailable
		}
	}
	if !r.Valid() || r.Binding.CaptureID != uid(row.CaptureID) || r.Binding.AttemptID != uid(row.AttemptID) || !r.Binding.NotBefore.Equal(row.NotBefore.Time) || !r.Binding.NotAfter.Equal(row.NotAfter.Time) {
		return value.APIExecution{}, value.ErrUnavailable
	}
	return r, nil
}
func (s *APIContextExecutions) ReadAPIContextWork(ctx context.Context, captureID string, i identity.Identity, recovery artifact.RecoveryProof) (app.APIContextWork, error) {
	var out app.APIContextWork
	if !authorization.UUID(captureID) || !i.Valid(i.VerifiedAt) || !recovery.Valid(recovery.ObservedAt) {
		return out, value.ErrInvalid
	}
	// The ledger normalizes errors returned through it; keep the step beside it.
	failed := ""
	fail := func(step string, e error) error { failed = step; return e }
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, err := s.guards.Recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return fail("recovery-lock", err)
		}
		stream, err := q.LockPermissionStream(ctx, id(s.root))
		if err != nil {
			return fail("permission-lock", err)
		}
		row, err := q.ReadPublicationCapture(ctx, custodydb.ReadPublicationCaptureParams{ID: id(captureID), RootID: id(s.root)})
		if err != nil {
			return fail("capture", value.ErrDenied)
		}
		out, err = apiWork(row)
		if err != nil {
			return fail("work", err)
		}
		projection, err := permissionProjection(ctx, q, stream, authorization.Target{ClusterID: out.Target.ClusterID, NamespaceUID: out.Target.Namespace.UID, WorkloadUID: out.Target.Workload.UID, PodUID: out.Target.PodUID})
		if err != nil {
			return fail("permission", value.ErrDenied)
		}
		if err = s.guards.Recovery.check(ctx, q, trust, s.root, recovery); err != nil {
			return fail("recovery-check", err)
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return fail("time", err)
		}
		eligible := authorization.ContextEligibility(i, projection, projection.Target, now.Time)
		if !eligible.Eligible {
			return fail("eligibility", value.ErrDenied)
		}
		if i.Principal != out.Actor || !now.Time.Before(out.Accepted.Deadline) {
			return fail("actor-deadline", value.ErrDenied)
		}
		return ctx.Err()
	})
	if err != nil {
		if failed != "" {
			return app.APIContextWork{}, sqlStep{failed, err}
		}
		return app.APIContextWork{}, err
	}
	return out, nil
}

// check locks recovery -> permission -> pool/allocation -> attempt -> capture,
// re-evaluating the same ordinary evaluator after every blocking SQL wait.
func (s *APIContextExecutions) checked(ctx context.Context, q *custodydb.Queries, c app.APIExecutionCheck, topology privacyvalue.PolicyTopology, fn func(custodydb.ContextCapture) error) error {
	trust, err := s.guards.Recovery.lock(ctx, q, s.root, c.Recovery)
	if err != nil {
		return sqlStep{"recovery-lock", err}
	}
	stream, err := q.LockPermissionStream(ctx, id(s.root))
	if err != nil {
		return sqlStep{"permission-lock", err}
	}
	e := c.Work.Accepted.Expectation
	pool, allocation, err := lockAllocation(ctx, q, e.Registration.AllocationID)
	if err != nil {
		return sqlStep{"allocation", err}
	}
	attempt, err := q.LockAttempt(ctx, id(e.Registration.Location.AttemptID))
	if err != nil {
		return sqlStep{"attempt", err}
	}
	accepted, err := q.LockContextCapture(ctx, custodydb.LockContextCaptureParams{ID: id(e.CaptureUID), RootID: id(s.root)})
	if err != nil {
		return sqlStep{"capture", err}
	}
	w, err := apiWork(accepted)
	if err != nil {
		return sqlStep{"work", err}
	}
	if w.Actor != c.Work.Actor || w.Target != c.Work.Target || w.IntentDigest != c.Work.IntentDigest || w.Accepted.Pin != c.Work.Accepted.Pin || !bytes.Equal(digest(w.Accepted.Expectation), digest(e)) {
		return sqlStep{"conflict", value.ErrConflict}
	}

	if !bytes.Equal(attempt.RequestDigest, digest(normalized(e.Registration))) || attempt.State != artifact.Reserved {
		return sqlStep{"attempt-state", value.ErrDenied}
	}
	check := func() error {
		if err := s.guards.Recovery.check(ctx, q, trust, s.root, c.Recovery); err != nil {
			return sqlStep{"recovery-check", err}
		}
		if err := s.guards.Retention.check(ctx, q, topology, c.Plan.Input.Retention.Proof, c.Plan.Input.Target.Target()); err != nil {
			return sqlStep{"retention-check", err}
		}
		projection, err := permissionProjection(ctx, q, stream, c.Eligibility.Target)
		if err != nil {
			return sqlStep{"permission", err}
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return sqlStep{"time", err}
		}
		eligible := authorization.ContextEligibility(c.Eligibility.VerifiedIdentity, projection, c.Eligibility.Target, now.Time)
		if !c.Valid(now.Time) || !eligible.Eligible || eligible.Principal != w.Actor || eligible.PermissionRevision != c.Eligibility.PermissionRevision || eligible.IdentityRevision != c.Eligibility.IdentityRevision || !slices.Equal(eligible.DefaultAudience, e.Audience) {
			return sqlStep{"eligibility", value.ErrDenied}
		}
		if err = current(ctx, q, pool, allocation, e.Registration, attempt.EffectiveExpiresAt.Time); err != nil {
			return sqlStep{"storage-current", err}
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return sqlStep{"time", err}
		}
		if !c.Valid(now.Time) || !now.Time.Before(eligible.ValidUntil) {
			return sqlStep{"expired", value.ErrExpired}
		}
		return ctx.Err()
	}
	if err = check(); err != nil {
		return sqlStep{"expired", err}
	}
	if err = fn(accepted); err != nil {
		return sqlStep{"effect", err}
	}
	return check()
}
func (s *APIContextExecutions) PrepareAPIExecution(ctx context.Context, c app.APIExecutionCheck) (value.APIExecution, bool, error) {
	var out value.APIExecution
	var first bool
	if !authorization.UUID(c.Work.Accepted.CaptureID) || c.Work.Accepted.Expectation.ExecutionClass != artifact.ContextAPIExecution {
		return out, false, value.ErrInvalid
	}
	topology, err := s.guards.Retention.observe(ctx, c.Work.Target.ClusterID)
	if err != nil {
		return out, false, err
	}
	// The ledger normalizes errors returned through it; keep the step beside it.
	failed := ""
	headroomRefused := false
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = value.APIExecution{}
		first = false
		headroomRefused = false
		err := s.checked(ctx, q, c, topology, func(accepted custodydb.ContextCapture) error {
			row, err := q.LockAPIExecution(ctx, custodydb.LockAPIExecutionParams{RootID: id(s.root), CaptureID: accepted.ID})
			if errors.Is(err, pgx.ErrNoRows) {
				e := c.Work.Accepted.Expectation
				p := c.Process.Binding
				b := value.Binding{ExecutionClass: artifact.ContextAPIExecution, ExecutorPodUID: p.PodUID, ExecutorAccountUID: p.AccountUID, OperationID: e.CaptureUID, CaptureID: e.CaptureUID, ActionID: e.ActionID, AttemptID: e.Registration.Location.AttemptID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PodUID: e.PodUID, CollectorEpoch: p.ProcessEpoch, ScopeDigest: e.PlanDigest, AuditDigest: c.Work.IntentDigest, NativeBytes: artifact.MaxContextBytes, NotBefore: c.CheckedAt.UTC(), NotAfter: c.ValidUntil.UTC()}
				copy(b.BudgetDigest[:], digest(normalized(e.Registration)))
				copy(b.AuthorityDigest[:], digest(struct {
					Process    value.APIProcessBinding
					Permission identity.Revision
					Identity   identity.Revision
				}{p, c.Eligibility.PermissionRevision, c.Eligibility.IdentityRevision}))
				bj, _ := json.Marshal(b)
				pj, _ := json.Marshal(p)
				ed := evidence.ContextExpectationDigest(e)
				// ADR-212: spend the first preparation only with at least one
				// second left after the blocking authority/storage locks. The
				// caller may be shorter than the original checked interval;
				// neither interval nor the stored binding is renewed here.
				now, timeErr := q.CurrentTime(ctx)
				if timeErr != nil {
					return sqlStep{"time", timeErr}
				}
				until := c.ValidUntil
				if deadline, ok := ctx.Deadline(); ok {
					until = identity.Earlier(until, deadline)
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				if until.Sub(now.Time) < time.Second {
					headroomRefused = true
					return sqlStep{"headroom", privacyapp.ErrUnavailable}
				}
				row, err = q.InsertAPIExecution(ctx, custodydb.InsertAPIExecutionParams{RootID: id(s.root), CaptureID: accepted.ID, AttemptID: accepted.AttemptID, BindingJson: bj, ProcessJson: pj, ExpectationDigest: ed[:], NotBefore: ts(b.NotBefore), NotAfter: ts(b.NotAfter), WriterProtocol: pgtype.Text{String: artifact.ContextWriterProtocol, Valid: true}})
				first = err == nil
			}
			if err != nil {
				return sqlStep{map[bool]string{true: "insert", false: "lock"}[first || errors.Is(err, pgx.ErrNoRows)], err}
			}
			out, err = apiExecution(row)
			if err != nil {
				return sqlStep{"read", err}
			}
			if out.Process != c.Process.Binding || out.ExpectationDigest != evidence.ContextExpectationDigest(c.Work.Accepted.Expectation) || out.Binding.ScopeDigest != c.Plan.ScopeDigest {
				return sqlStep{"conflict", value.ErrConflict}
			}
			now, err := q.CurrentTime(ctx)
			if err != nil {
				return err
			}
			// Exact existing preparation is passive even after its original
			// interval: the runner must classify it uncertain without keys or
			// another start. checked still requires current authority before
			// and after this result, and every active effect keeps its cutoff.
			if (first || out.Phase != "prepared") && !now.Time.Before(out.Binding.NotAfter) {
				return sqlStep{"expired", value.ErrExpired}
			}
			return nil
		})
		var st sqlStep
		if errors.As(err, &st) {
			failed = st.FixedStep()
		}
		return err
	})
	if err != nil {
		err = apiPreparationRefusalError(err, headroomRefused)
		if failed != "" {
			return value.APIExecution{}, false, sqlStep{failed, err}
		}
		return value.APIExecution{}, false, err
	}
	return out, first, nil
}

func apiPreparationRefusalError(err error, headroomRefused bool) error {
	// Ordinary custody normalization of this known refusal is "client".
	// Expiry during rollback instead reports "deadline" and must survive.
	var cause ledgerCause
	if headroomRefused && errors.As(err, &cause) && cause.cause == "client" {
		return value.ErrUnavailable
	}
	return err
}

func (s *APIContextExecutions) BindAPIStart(ctx context.Context, c app.APIExecutionCheck, r value.APIExecution, p value.PreparedStart) (value.APIExecution, error) {
	return s.changeAPIStart(ctx, c, r, func(q *custodydb.Queries, old value.APIExecution) (custodydb.ContextExecution, error) {
		if !authorization.UUID(p.ObjectUID) || !identity.Text(p.ResourceVersion, 128) {
			return custodydb.ContextExecution{}, value.ErrInvalid
		}
		if old.ObjectUID != "" {
			if old.ObjectUID != p.ObjectUID {
				return custodydb.ContextExecution{}, value.ErrConflict
			}
			return q.ReadAPIExecution(ctx, custodydb.ReadAPIExecutionParams{RootID: id(s.root), CaptureID: id(r.Binding.CaptureID)})
		}
		return q.BindAPIStart(ctx, custodydb.BindAPIStartParams{RootID: id(s.root), CaptureID: id(r.Binding.CaptureID), ObjectUid: id(p.ObjectUID)})
	})
}
func (s *APIContextExecutions) RecordAPIStart(ctx context.Context, c app.APIExecutionCheck, r value.APIExecution, d value.Disposition) (value.APIExecution, error) {
	return s.changeAPIStart(ctx, c, r, func(q *custodydb.Queries, old value.APIExecution) (custodydb.ContextExecution, error) {
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return custodydb.ContextExecution{}, err
		}
		if !d.MayStart || d.Phase != value.StartCommitted || d.ObjectUID != old.ObjectUID || d.CommittedAt.Before(old.Binding.NotBefore) || !d.CommittedAt.Before(old.Binding.NotAfter) || d.CommittedAt.After(now.Time) || !now.Time.Before(d.ValidUntil) || d.ValidUntil.After(old.Binding.NotAfter) || d.ValidUntil.After(c.ValidUntil) {
			return custodydb.ContextExecution{}, value.ErrDenied
		}
		if old.Phase != "prepared" {
			return custodydb.ContextExecution{}, value.ErrConflict
		}
		return q.RecordAPIStart(ctx, custodydb.RecordAPIStartParams{RootID: id(s.root), CaptureID: id(r.Binding.CaptureID), StartedAt: ts(d.CommittedAt)})
	})
}
func (s *APIContextExecutions) changeAPIStart(ctx context.Context, c app.APIExecutionCheck, r value.APIExecution, change func(*custodydb.Queries, value.APIExecution) (custodydb.ContextExecution, error)) (value.APIExecution, error) {
	var out value.APIExecution
	if !r.Valid() || r.RootID != s.root || r.Process != c.Process.Binding {
		return out, value.ErrInvalid
	}
	topology, err := s.guards.Retention.observe(ctx, c.Work.Target.ClusterID)
	if err != nil {
		return out, err
	}
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		return s.checked(ctx, q, c, topology, func(_ custodydb.ContextCapture) error {
			row, err := q.LockAPIExecution(ctx, custodydb.LockAPIExecutionParams{RootID: id(s.root), CaptureID: id(r.Binding.CaptureID)})
			if err != nil {
				return err
			}
			old, err := apiExecution(row)
			if err != nil {
				return err
			}
			if old.Binding != r.Binding || old.Process != r.Process || old.ExpectationDigest != r.ExpectationDigest {
				return value.ErrConflict
			}
			now, err := q.CurrentTime(ctx)
			if err != nil {
				return err
			}
			if !now.Time.Before(old.Binding.NotAfter) {
				return value.ErrExpired
			}
			row, err = change(q, old)
			if err != nil {
				return err
			}
			out, err = apiExecution(row)
			return err
		})
	})
	if err != nil {
		return value.APIExecution{}, err
	}
	return out, nil
}
func (s *APIContextExecutions) RecordAPIOutcome(ctx context.Context, r value.APIExecution, process value.APIProcessObservation) (value.APIExecution, error) {
	if r.WriterProtocol == artifact.ContextWriterProtocol && r.Phase == "stored" {
		return value.APIExecution{}, value.ErrDenied
	}
	return s.recordAPIOutcome(ctx, r, process, nil, artifact.RecoveryProof{})
}
func (s *APIContextExecutions) RecordAPIStoredCompletion(ctx context.Context, r value.APIExecution, c artifact.ContextWriterCompletion, process value.APIProcessObservation, recovery artifact.RecoveryProof) (value.APIExecution, error) {
	if r.WriterProtocol != artifact.ContextWriterProtocol || r.Phase != "stored" || c.Copies != r.Copies || !c.StoredAt.Equal(r.CompletedAt) || recovery.InstallationID != r.Process.InstallationID || recovery.IssuerEpoch != r.Process.IssuerEpoch {
		return value.APIExecution{}, value.ErrInvalid
	}
	return s.recordAPIOutcome(ctx, r, process, &c, recovery)
}
func (s *APIContextExecutions) recordAPIOutcome(ctx context.Context, r value.APIExecution, process value.APIProcessObservation, completion *artifact.ContextWriterCompletion, recovery artifact.RecoveryProof) (value.APIExecution, error) {
	var out value.APIExecution
	if !r.Valid() || r.RootID != s.root || r.Phase == "prepared" || r.Phase == "started" || process.Binding != r.Process {
		return out, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		var trust custodydb.FleetCurrentTrust
		if completion != nil {
			var err error
			trust, err = s.guards.Recovery.lock(ctx, q, s.root, recovery)
			if err != nil {
				return err
			}
		}
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		c, err := q.LockContextCapture(ctx, custodydb.LockContextCaptureParams{ID: id(r.Binding.CaptureID), RootID: id(s.root)})
		if err != nil {
			return err
		}
		row, err := q.LockAPIExecution(ctx, custodydb.LockAPIExecutionParams{RootID: id(s.root), CaptureID: c.ID})
		if err != nil {
			return err
		}
		old, err := apiExecution(row)
		if err != nil {
			return err
		}
		if old.WriterProtocol != r.WriterProtocol || old.Binding != r.Binding || old.Process != r.Process || old.ObjectUID != r.ObjectUID || old.ExpectationDigest != r.ExpectationDigest || !old.StartedAt.Equal(r.StartedAt) {
			return value.ErrConflict
		}
		if old.Phase != "started" {
			if !reflect.DeepEqual(old, r) {
				return value.ErrConflict
			}
			out = old
			if completion != nil {
				w, err := q.ReadContextWriterCompletion(ctx, custodydb.ReadContextWriterCompletionParams{RootID: id(s.root), AttemptID: c.AttemptID})
				if err != nil {
					return err
				}
				want := privacyapp.ContextWriterDigest(*completion)
				if !bytes.Equal(w.CompletionDigest, want[:]) {
					return value.ErrConflict
				}
				if err = s.guards.Recovery.check(ctx, q, trust, s.root, recovery); err != nil {
					return err
				}
			}
			now, err := q.CurrentTime(ctx)
			if err != nil {
				return err
			}
			if !process.Valid(now.Time) || completion != nil && !recovery.Valid(now.Time) {
				return value.ErrExpired
			}
			return ctx.Err()
		}
		e, err := acceptedPublication(c)
		if err != nil {
			return err
		}
		if r.Phase == "stored" && (r.Copies.Validate(e.Registration) != nil || !r.CompletedAt.Before(e.Registration.WriteUntil)) {
			return value.ErrDenied
		}
		if completion != nil && (!completion.Valid(e.Registration) || completion.ExpectationDigest != evidence.ContextExpectationDigest(e) || completion.RegistrationDigest != privacyapp.RegistrationDigest(e.Registration)) {
			return value.ErrDenied
		}

		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !process.Valid(now.Time) || r.CompletedAt.After(now.Time) {
			return value.ErrExpired
		}
		var copiesJSON, copiesDigest []byte
		if r.Phase == "stored" {
			copiesJSON, _ = json.Marshal(r.Copies)
			copiesDigest = digest(r.Copies)
		}
		acquiredAt := pgtype.Timestamptz{}
		if !r.AcquiredAt.IsZero() {
			acquiredAt = ts(r.AcquiredAt)
		}
		row, err = q.RecordAPIOutcome(ctx, custodydb.RecordAPIOutcomeParams{RootID: id(s.root), CaptureID: c.ID, Phase: r.Phase, AcquiredAt: acquiredAt, CompletedAt: ts(r.CompletedAt), CopiesJson: copiesJSON, CopiesDigest: copiesDigest})
		if err != nil {
			return err
		}
		out, err = apiExecution(row)
		if err != nil {
			return err
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !process.Valid(now.Time) || completion != nil && !recovery.Valid(now.Time) {
			return value.ErrExpired
		}
		if completion != nil {
			if completion.ClosedAt.After(now.Time) {
				return value.ErrInvalid
			}
			incarnation, err := q.ReadContextDatabaseIncarnation(ctx, id(recovery.InstallationID))
			if err != nil {
				return err
			}
			ed := app.APIExecutionDigest(r)
			cd := privacyapp.ContextWriterDigest(*completion)
			err = q.InsertContextWriterCompletion(ctx, custodydb.InsertContextWriterCompletionParams{RootID: id(s.root), CaptureID: c.ID, AttemptID: c.AttemptID, RegistrationDigest: completion.RegistrationDigest[:], ExpectationDigest: completion.ExpectationDigest[:], CopiesDigest: digest(r.Copies), ExecutionDigest: ed[:], CompletionDigest: cd[:], InstallationID: id(recovery.InstallationID), IssuerEpoch: id(recovery.IssuerEpoch), PostmasterAt: incarnation.PostmasterAt, DatabaseOid: incarnation.DatabaseOid, StoredAt: ts(completion.StoredAt), ClosedAt: ts(completion.ClosedAt)})
			if err != nil {
				return err
			}
			if err = s.guards.Recovery.check(ctx, q, trust, s.root, recovery); err != nil {
				return err
			}
			now, err = q.CurrentTime(ctx)
			if err != nil {
				return err
			}
			if !process.Valid(now.Time) || completion != nil && !recovery.Valid(now.Time) {
				return value.ErrExpired
			}
		}
		return ctx.Err()
	})
	if err != nil {
		return value.APIExecution{}, err
	}
	return out, nil
}

var _ app.APIExecutionReader = (*APIContextExecutions)(nil)
var _ app.APIExecutionPreparer = (*APIContextExecutions)(nil)
var _ app.APIExecutionRecorder = (*APIContextExecutions)(nil)

// sqlStep names where an execution transaction stopped, for operator
// diagnostics; its class is the wrapped error.
type sqlStep struct {
	step string
	err  error
}

func (e sqlStep) Error() string { return "api execution " + e.step }
func (e sqlStep) Unwrap() error { return e.err }
func (e sqlStep) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}
