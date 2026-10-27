package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PolicyTriggers is the ADR-228 trigger ledger: Pod restart watermarks,
// deduplicated occurrences, shared workload budgets, execution spend and
// content-free suppression counts. It admits no capture: an occurrence is
// only the right to attempt one ordinary, fully checked context capture.
type PolicyTriggers struct {
	ledger             *Ledger
	root, installation string
}

func NewPolicyTriggers(ctx context.Context, pool *pgxpool.Pool, root, installation string) (*PolicyTriggers, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if why := schemaCompatible(ctx, pool); why != "" {
		return nil, schemaRefusal(value.ErrUnavailable, why)
	}
	return &PolicyTriggers{ledger: l, root: root, installation: installation}, nil
}

// Tick evaluates one observation under the policy-row and workload-window
// locks: replay and concurrent duplicate polls are no-ops, and the shared
// workload budget, the policy's own budget and the accepted execution
// ceiling all hold before an occurrence exists.
func (s *PolicyTriggers) Tick(ctx context.Context, in value.PolicyTick) ([]value.PolicyOccurrence, error) {
	a, o := in.Authority, in.Observation
	if s == nil || !in.Policy.Valid() || a.InstallationID != s.installation || o.ClusterID != a.ClusterID || o.Namespace.UID != a.NamespaceUID || o.Workload.UID != a.WorkloadUID || in.Policy.ClusterID != a.ClusterID || len(o.Pods) > in.Policy.ObservedPods || !o.Answers(in.Policy.Request()) {
		return nil, value.ErrInvalid
	}
	detector := in.Policy.Kind()
	var out []value.PolicyOccurrence
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = nil
		row, err := q.LockPolicySource(ctx, custodydb.LockPolicySourceParams{RootID: id(s.root), PolicyUid: a.PolicyUID})
		if err != nil {
			return err
		}
		if !row.ActiveID.Valid {
			// Deactivated (ADR-229) after this cycle listed the policy.
			return value.ErrUnavailable
		}
		accepted, err := q.ReadPolicyAcceptance(ctx, custodydb.ReadPolicyAcceptanceParams{RootID: id(s.root), ID: row.ActiveID})
		if err != nil {
			return err
		}
		record, err := decodePolicy(accepted)
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		n := now.Time
		source := policySource(row)
		// Spending requires the current acknowledged acceptance of exactly this
		// scope and a current source; the capture path checks everything again.
		if !row.ActiveID.Valid || !accepted.AcknowledgedAt.Valid || source.Deleted || source.Suspended || !source.Valid(n) || record.IntentVersion != row.IntentVersion || record.Authority.ScopeDigest != a.ScopeDigest || !record.Authority.Valid(n) || !o.Valid(n) {
			return value.ErrUnavailable
		}
		observed := make([]string, 0, len(o.Pods))
		for _, p := range o.Pods {
			observed = append(observed, p.UID)
		}
		marks, err := q.ListPolicyWatermarks(ctx, custodydb.ListPolicyWatermarksParams{RootID: id(s.root), PolicyUid: a.PolicyUID, Column3: observed, Detector: detector})
		if err != nil {
			return err
		}
		previous := make(map[string]value.PodMark, len(marks))
		for _, m := range marks {
			previous[m.PodUid] = value.PodMark{Value: m.Restarts, Armed: m.Armed}
		}
		next, fired := value.TriggerDelta(in.Policy, previous, o)
		pods, counts, armed := make([]string, 0, len(next)), make([]int64, 0, len(next)), make([]bool, 0, len(next))
		for pod, m := range next {
			pods, counts, armed = append(pods, pod), append(counts, m.Value), append(armed, m.Armed)
		}
		// Watermarks only rise: a Pod missing from one poll keeps its count, so
		// its next restart still fires. Pods unseen for ten minutes are pruned.
		if err = q.PrunePolicyWatermarks(ctx, custodydb.PrunePolicyWatermarksParams{RootID: id(s.root), PolicyUid: a.PolicyUID, LastSeen: ts(n.Add(-policyWatermarkRetention))}); err != nil {
			return err
		}
		if len(pods) > 0 {
			if err = q.UpsertPolicyWatermarks(ctx, custodydb.UpsertPolicyWatermarksParams{RootID: id(s.root), PolicyUid: a.PolicyUID, PodUids: pods, Restarts: counts, Seen: ts(n), Detector: detector, Armed: armed}); err != nil {
				return err
			}
		}
		suppress := map[string]int64{}
		// ADR-241: a log Pod whose window held a record longer than
		// maxRecordBytes that was dropped, counted once per Pod and poll.
		for _, p := range o.Pods {
			if p.Overlong {
				suppress["overlong"]++
			}
		}
		for _, c := range fired {
			if c.Missed > 0 {
				suppress["coalesced"] += c.Missed
			}
			shared, err := s.window(ctx, q, a, "", n)
			if err != nil {
				return err
			}
			own, err := s.window(ctx, q, a, a.PolicyUID, n)
			if err != nil {
				return err
			}
			// The policy row lock serializes ticks; an existing occurrence of this
			// exact restart is a replay and spends nothing.
			if _, err = q.FindPolicyOccurrence(ctx, custodydb.FindPolicyOccurrenceParams{RootID: id(s.root), PolicyUid: a.PolicyUID, PodUid: c.PodUID, Restarts: c.Restarts}); err == nil {
				continue
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if !admits(shared, n, value.WorkloadTriggerInterval, value.WorkloadTriggerBurst) || !admits(own, n, in.Policy.Interval, in.Policy.Burst) {
				suppress["cooldown"]++
				continue
			}
			spent, err := q.SpendPolicyExecution(ctx, custodydb.SpendPolicyExecutionParams{RootID: id(s.root), ID: row.ActiveID})
			if err != nil {
				return err
			}
			if spent != 1 {
				suppress["budget"]++
				continue
			}
			newID, err := q.NewPolicyAcceptanceID(ctx)
			if err != nil {
				return err
			}
			occurrence := value.PolicyOccurrence{ID: uid(newID), PolicyUID: a.PolicyUID, PodUID: c.PodUID, Restarts: c.Restarts}
			inserted, err := q.InsertPolicyOccurrence(ctx, custodydb.InsertPolicyOccurrenceParams{ID: newID, RootID: id(s.root), PolicyUid: a.PolicyUID, AcceptanceID: row.ActiveID, ClusterID: id(a.ClusterID), WorkloadUid: a.WorkloadUID, PodUid: c.PodUID, Restarts: c.Restarts, Detector: detector})
			if err != nil {
				return err
			}
			if inserted != 1 {
				return value.ErrConflict
			}
			for _, w := range []struct {
				policy   string
				tat      time.Time
				interval time.Duration
			}{{"", shared, value.WorkloadTriggerInterval}, {a.PolicyUID, own, in.Policy.Interval}} {
				if err = q.UpdatePolicyWindow(ctx, custodydb.UpdatePolicyWindowParams{RootID: id(s.root), ClusterID: id(a.ClusterID), WorkloadUid: a.WorkloadUID, PolicyUid: w.policy, Tat: ts(later(w.tat, n).Add(w.interval))}); err != nil {
					return err
				}
			}
			out = append(out, occurrence)
		}
		for _, reason := range []string{"budget", "coalesced", "cooldown", "overlong"} {

			if suppress[reason] > 0 {
				if err = s.suppress(ctx, q, a.PolicyUID, reason, n, suppress[reason]); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, captureError(err)
	}
	return out, nil
}

// window locks (creating at now) one budget row and returns its arrival time.
func (s *PolicyTriggers) window(ctx context.Context, q *custodydb.Queries, a authorization.AcceptedPolicyAuthority, policy string, now time.Time) (time.Time, error) {
	t, err := q.LockPolicyWindow(ctx, custodydb.LockPolicyWindowParams{RootID: id(s.root), ClusterID: id(a.ClusterID), WorkloadUid: a.WorkloadUID, PolicyUid: policy, Tat: ts(now)})
	if err != nil {
		return time.Time{}, err
	}
	return t.Time.UTC(), nil
}

// admits is the generic cell rate test: an emission at now conforms while
// the theoretical arrival time is at most (burst-1) intervals ahead.
func admits(tat, now time.Time, interval time.Duration, burst int) bool {
	return !tat.After(now.Add(time.Duration(burst-1) * interval))
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func (s *PolicyTriggers) suppress(ctx context.Context, q *custodydb.Queries, policy, reason string, at time.Time, count int64) error {
	return q.CountPolicySuppression(ctx, custodydb.CountPolicySuppressionParams{RootID: id(s.root), PolicyUid: policy, Reason: reason, FirstAt: ts(at), Count: min(count, 2147483647)})
}

// policyWatermarkRetention is how long an unseen Pod keeps its watermark.
const policyWatermarkRetention = 10 * time.Minute

// SettleOccurrences refuses, as unavailable, every occurrence still open
// after age: its capture attempt ended without a record (a hub-api restart,
// a failed RecordOccurrence). The execution stays spent (ADR-223); nothing
// is resumed or retried.
func (s *PolicyTriggers) SettleOccurrences(ctx context.Context, age time.Duration) error {
	if s == nil || age <= 0 {
		return value.ErrInvalid
	}
	return captureError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		policies, err := q.SettleOpenPolicyOccurrences(ctx, custodydb.SettleOpenPolicyOccurrencesParams{RootID: id(s.root), CreatedAt: ts(now.Time.Add(-age))})
		if err != nil {
			return err
		}
		counts := map[string]int64{}
		for _, p := range policies {
			counts[p]++
		}
		for p, n := range counts {
			if err = s.suppress(ctx, q, p, "unavailable", now.Time, n); err != nil {
				return err
			}
		}
		return nil
	}))
}

// RecordOccurrence links the occurrence's one capture, or records why none
// was admitted (capacity, authority or unavailable) as a suppression. It
// never retries.
func (s *PolicyTriggers) RecordOccurrence(ctx context.Context, o value.PolicyOccurrence, captureID, refusal string) error {
	if s == nil || !authorization.UUID(o.ID) || !identity.Text(o.PolicyUID, 64) || (captureID == "") == (refusal == "") || captureID != "" && !authorization.UUID(captureID) || refusal != "" && refusal != "capacity" && refusal != "authority" && refusal != "unavailable" {
		return value.ErrInvalid
	}
	return captureError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if captureID != "" {
			n, err := q.LinkPolicyOccurrence(ctx, custodydb.LinkPolicyOccurrenceParams{RootID: id(s.root), ID: id(o.ID), CaptureID: id(captureID)})
			if err != nil {
				return err
			}
			if n != 1 {
				return value.ErrConflict
			}
			return nil
		}
		n, err := q.RefusePolicyOccurrence(ctx, custodydb.RefusePolicyOccurrenceParams{RootID: id(s.root), ID: id(o.ID)})
		if err != nil {
			return err
		}
		if n != 1 {
			return value.ErrConflict
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		return s.suppress(ctx, q, o.PolicyUID, refusal, now.Time, 1)
	}))
}

// ActivePolicies lists at most 64 policies to poll. Listing confers nothing:
// each tick re-reads the source and the current accepted authority.
func (s *PolicyTriggers) ActivePolicies(ctx context.Context) ([]value.ActivePolicy, error) {
	var out []value.ActivePolicy
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.ListActivePolicies(ctx, id(s.root))
		if err != nil {
			return err
		}
		if len(rows) > 64 {
			return value.ErrCapacity
		}
		out = make([]value.ActivePolicy, 0, len(rows))
		for _, r := range rows {
			out = append(out, value.ActivePolicy{PolicyUID: r.PolicyUid, Name: r.Name, NamespaceUID: r.NamespaceUid})
		}
		return nil
	})
	if err != nil {
		return nil, captureError(err)
	}
	return out, nil
}

func (s *PolicyTriggers) Status(ctx context.Context, policy string) (value.PolicyStatus, error) {
	var out value.PolicyStatus
	if s == nil || !identity.Text(policy, 64) {
		return out, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.ReadPolicySourceRow(ctx, custodydb.ReadPolicySourceRowParams{RootID: id(s.root), PolicyUid: policy})
		if errors.Is(err, pgx.ErrNoRows) {
			return value.ErrUnavailable
		}
		if err != nil {
			return err
		}
		out = value.PolicyStatus{PolicyUID: policy, Generation: row.Generation, IntentVersion: row.IntentVersion, Suspended: row.Suspended, Deleted: row.Deleted, SourceObservedAt: row.ObservedAt.Time.UTC(), SourceFreshUntil: row.FreshUntil.Time.UTC()}
		if len(row.CreatorJson) > 0 {
			var creator identity.Principal
			if json.Unmarshal(row.CreatorJson, &creator) != nil || !creator.Valid() {
				return value.ErrUnavailable
			}
			out.Creator = &creator
		}
		var accepted custodydb.PolicyAcceptance
		if row.ActiveID.Valid {
			accepted, err = q.ReadPolicyAcceptance(ctx, custodydb.ReadPolicyAcceptanceParams{RootID: id(s.root), ID: row.ActiveID})
		} else {
			// A cleared active_id with an earlier acceptance is a deactivated
			// policy (ADR-229); without one it was never accepted.
			accepted, err = q.LatestPolicyAcceptance(ctx, custodydb.LatestPolicyAcceptanceParams{RootID: id(s.root), PolicyUid: policy})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
		}
		if err != nil {
			return err
		}
		record, err := decodePolicy(accepted)
		if err != nil {
			return err
		}
		a := record.Authority
		if !row.ActiveID.Valid {
			out.DeactivatedID = record.ID
		}
		if row.ActiveID.Valid {
			out.ActiveID = record.ID
		}
		out.Authority, out.ExecutionsSpent, out.MaxExecutions, out.NotAfter, out.AcceptedIntentVersion, out.AcceptedGeneration = a, accepted.ExecutionsSpent, a.Limits.MaxExecutions, a.NotAfter.UTC(), record.IntentVersion, record.Source.Revision.Generation
		out.ClusterID, out.NamespaceUID, out.WorkloadUID = a.ClusterID, a.NamespaceUID, a.WorkloadUID
		if record.Sharing != nil {
			out.Sharing = &value.PolicySharingStatus{Instruction: *record.Sharing, Spent: int64(accepted.SharesSpent)}
			if accepted.SharingRevokedAt.Valid {
				out.Sharing.RevokedAt = accepted.SharingRevokedAt.Time.UTC()
			}
			if accepted.SharingStoppedAt.Valid {
				out.Sharing.StoppedAt = accepted.SharingStoppedAt.Time.UTC()
			}
		}
		if out.WatchedPods, err = q.CountPolicyWatermarks(ctx, custodydb.CountPolicyWatermarksParams{RootID: id(s.root), PolicyUid: policy}); err != nil {
			return err
		}
		counts, err := q.CountPolicyOccurrences(ctx, custodydb.CountPolicyOccurrencesParams{RootID: id(s.root), PolicyUid: policy})
		if err != nil {
			return err
		}
		out.Occurrences, out.Captured = counts.Total, counts.Captured
		recent, err := q.ListPolicyOccurrences(ctx, custodydb.ListPolicyOccurrencesParams{RootID: id(s.root), PolicyUid: policy})
		if err != nil {
			return err
		}
		for _, r := range recent {
			o := value.PolicyOccurrenceStatus{ID: uid(r.ID), Detector: r.Detector, Restarts: r.Restarts, CreatedAt: r.CreatedAt.Time.UTC()}
			if r.CaptureID.Valid {
				o.CaptureID = uid(r.CaptureID)
			}
			if r.Outcome.Valid {
				o.Outcome = r.Outcome.String
			}
			out.Recent = append(out.Recent, o)
		}
		rows, err := q.ListPolicySuppressions(ctx, custodydb.ListPolicySuppressionsParams{RootID: id(s.root), PolicyUid: policy})
		if err != nil {
			return err
		}
		for _, r := range rows {
			out.Suppressions = append(out.Suppressions, value.PolicySuppression{Reason: r.Reason, Count: r.Count, FirstAt: r.FirstAt.Time.UTC(), LastAt: r.LastAt.Time.UTC()})
		}
		return nil
	})
	if err != nil {
		return value.PolicyStatus{}, captureError(err)
	}
	return out, nil
}

// DeactivatePolicy clears the policy's current acceptance (ADR-229) under the
// policy-source row lock, so a tick after it admits nothing and every
// capture eligibility check refuses the executor. It refunds no spend and
// deletes no occurrence, capture or evidence. Repeating it for the same,
// already deactivated acceptance is a replay; another current acceptance (a
// concurrent replacement) is a conflict.
func (s *PolicyTriggers) DeactivatePolicy(ctx context.Context, policy, acceptance string) (bool, error) {
	replay := false
	if s == nil || !identity.Text(policy, 64) || !authorization.UUID(acceptance) {
		return false, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		replay = false
		row, err := q.LockPolicySource(ctx, custodydb.LockPolicySourceParams{RootID: id(s.root), PolicyUid: policy})
		if errors.Is(err, pgx.ErrNoRows) {
			return value.ErrUnavailable
		}
		if err != nil {
			return err
		}
		if row.ActiveID.Valid {
			if uid(row.ActiveID) != acceptance {
				return value.ErrConflict
			}
			n, err := q.DeactivatePolicySource(ctx, custodydb.DeactivatePolicySourceParams{RootID: id(s.root), PolicyUid: policy, ActiveID: row.ActiveID})
			if err != nil {
				return err
			}
			if n != 1 {
				return value.ErrConflict
			}
			return nil
		}
		latest, err := q.LatestPolicyAcceptance(ctx, custodydb.LatestPolicyAcceptanceParams{RootID: id(s.root), PolicyUid: policy})
		if errors.Is(err, pgx.ErrNoRows) {
			return value.ErrUnavailable
		}
		if err != nil {
			return err
		}
		if uid(latest.ID) != acceptance {
			return value.ErrConflict
		}
		replay = true
		return nil
	})
	if err != nil {
		return false, captureError(err)
	}
	return replay, nil
}

// Delegation resolves the sole automation-bearing AccessBinding whose scope
// covers the workload (ADR-059: a sole qualifying binding is chosen
// automatically; none or several requires a visible operator choice).
func (s *PolicyTriggers) Delegation(ctx context.Context, target authorization.Target) (identity.Revision, error) {
	if !target.Valid() {
		return identity.Revision{}, value.ErrInvalid
	}
	return s.WorkloadDelegation(ctx, authorization.WorkloadTarget{ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID})
}

// WorkloadDelegation selects the sole current automation basis without
// inventing a Pod identity for policy activation.
func (s *PolicyTriggers) WorkloadDelegation(ctx context.Context, target authorization.WorkloadTarget) (identity.Revision, error) {
	var out identity.Revision
	if s == nil || !target.Valid() {
		return out, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		stream, err := q.SharePermissionStream(ctx, id(s.root))
		if err != nil {
			return err
		}
		rows, err := q.FindAutomationBases(ctx, custodydb.FindAutomationBasesParams{StreamID: stream.ID, ClusterID: id(target.ClusterID), NamespaceUid: target.NamespaceUID, Column4: target.WorkloadUID})
		if err != nil {
			return err
		}
		if len(rows) != 1 || len(rows[0].SpecDigest) != 32 {
			return value.ErrDenied
		}
		out = identity.Revision{UID: rows[0].Uid, Generation: rows[0].Generation}
		copy(out.Digest[:], rows[0].SpecDigest)
		return nil
	})
	if err != nil {
		return identity.Revision{}, captureError(err)
	}
	return out, nil
}

// ActiveClusterPolicies counts the other accepted, unexpired policies whose
// workload is in the cluster (the per-cluster polling bound).
func (s *PolicyTriggers) ActiveClusterPolicies(ctx context.Context, cluster, except string) (int64, error) {
	var out int64
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		var err error
		out, err = q.CountActiveClusterPolicies(ctx, custodydb.CountActiveClusterPoliciesParams{RootID: id(s.root), PolicyUid: except, Column3: cluster})
		return err
	})
	return out, captureError(err)
}

// AcceptanceByNonce returns the immutable acceptance of an earlier
// activation with the same derived nonce, so a retried activation returns
// its original receipt instead of conflicting on a new issue time.
func (s *PolicyTriggers) AcceptanceByNonce(ctx context.Context, nonce string) (value.PolicyAcceptance, bool, error) {
	var out value.PolicyAcceptance
	found := false
	if s == nil || !authorization.UUID(nonce) {
		return out, false, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.FindPolicyNonce(ctx, custodydb.FindPolicyNonceParams{RootID: id(s.root), Nonce: id(nonce)})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out, err = decodePolicy(row)
		found = err == nil
		return err
	})
	if err != nil {
		return value.PolicyAcceptance{}, false, captureError(err)
	}
	return out, found, nil
}
