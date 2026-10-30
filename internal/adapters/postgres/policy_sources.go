package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	capacity "asservat.local/asservat/internal/application/capacity"
	app "asservat.local/asservat/internal/application/capture"
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PolicySources owns ordinary ongoing source commitments. It cannot create a
// capture/occurrence, issue raw observation authority or refund uncertain spend.
// The existing policy-automation SQL duty supplies this private facet.
type PolicySources struct {
	ledger             *Ledger
	root, installation string
	guards             EffectTransactionGuards
}

var _ app.PolicySourceLedger = (*PolicySources)(nil)

func NewPolicySources(ctx context.Context, pool *pgxpool.Pool, root, installation string, guards EffectTransactionGuards) (*PolicySources, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) || guards.Recovery == nil || guards.Retention == nil || guards.Recovery.root != root || guards.Retention.root != root || guards.Recovery.installation != installation {
		return nil, value.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, err
	}
	return &PolicySources{l, root, installation, guards}, nil
}

func sourceCheckCurrent(in app.PolicySourceCheck, now time.Time) bool {
	p := in.Policy.Recorder
	if p == nil {
		return false
	}
	age, ageErr := time.ParseDuration(p.Action.RingMaxAge)
	if ageErr != nil || age <= 0 || age > in.Retention.ExpiresAt.Sub(in.Retention.AnchorAt) {
		return false
	}
	return in.Policy.Valid() && p != nil && p.Action.ExecutionMode == "ongoing" && p.Action.PacketProfile == "networkHeaders" &&
		!compiler.RawBytePredicate(p.Action.Filter) && in.Authority.Valid(now) &&
		in.Target.ExecutionClass == artifact.ContextAPIExecution && in.Target.Valid(now) && in.Node.Valid(now) &&
		in.Target.Request.ClusterID == in.Authority.ClusterID && in.Target.Request.Namespace.UID == in.Authority.NamespaceUID && in.Target.Request.Workload.UID == in.Authority.WorkloadUID &&
		in.Target.Request.PodUID == in.Node.PodUID && in.Recovery.Valid(now) && in.Settings.Validate(now) == nil &&
		identity.Fresh(in.ObservedAt, in.ValidUntil, now, 5*time.Second) && now.Before(in.Retention.ValidUntil) && in.Retention.Target == in.Target.Target() && in.Retention.Proof.Valid(now) &&
		authorization.UUID(in.SourceID) && authorization.UUID(in.Fence) && in.BytesPerSecond > 0 && in.BytesPerSecond <= collector.MaxInputRate && in.SourceSlots > 0 && in.SourceSlots <= collector.MaxActiveSources &&
		in.InitialCredit >= 0 && in.ExpectedCredit >= 0 && in.AdditionalCredit >= 0 && in.ExpectedCredit <= math.MaxInt64-in.AdditionalCredit &&
		((!in.Initial && in.InitialCredit == 0) || (in.Initial && in.InitialCredit > 0 && in.ExpectedCredit == 0 && in.AdditionalCredit == 0))
}

func (s *PolicySources) AdmitSource(ctx context.Context, in app.PolicySourceCheck) (app.PolicySourceAdmission, error) {
	var out app.PolicySourceAdmission
	if s == nil || ctx == nil || ctx.Err() != nil || !sourceCheckCurrent(in, time.Now()) || in.Authority.InstallationID != s.installation {
		return out, value.ErrInvalid
	}
	// bound names the earliest deadline for failure counters only.
	entered, until, bound := time.Now(), in.ValidUntil, "cohort"
	narrow := func(name string, t time.Time) {
		if t.Before(until) {
			until, bound = t, name
		}
	}
	narrow("target", in.Target.FreshUntil)
	narrow("node", in.Node.FreshUntil)
	narrow("recovery", in.Recovery.FreshUntil)
	narrow("retention", in.Retention.ValidUntil)
	narrow("settings", in.Settings.FreshUntil)
	call, end := context.WithDeadline(ctx, until)
	defer end()
	var cutoff *time.Timer
	var cutoffDone chan struct{}
	stopCutoff := func() {
		if cutoff != nil && !cutoff.Stop() {
			<-cutoffDone
		}
		cutoff = nil
	}
	defer stopCutoff()
	// step names the bounded admission step for content-free failure counters.
	step := "topology"
	topology, err := s.guards.Retention.observe(call, in.Authority.ClusterID)
	if err != nil {
		return out, app.StagedSourceError("admit-"+step, err)
	}
	err = s.ledger.transaction(call, func(q *custodydb.Queries) error {
		step = "recovery"
		out = app.PolicySourceAdmission{}
		stopCutoff()
		trust, err := s.guards.Recovery.lock(call, q, s.root, in.Recovery)
		if err != nil {
			return err
		}
		step = "permissions"
		permissions, err := q.LockPermissionStream(call, id(s.root))
		if err != nil {
			return err
		}
		policy, err := q.LockPolicySource(call, custodydb.LockPolicySourceParams{RootID: id(s.root), PolicyUid: in.Authority.PolicyUID})
		if err != nil {
			return err
		}
		step = "accepted"
		accepted, record, err := acceptedPolicyIn(call, q, s.root, s.installation, trust, policy)
		if err != nil {
			return err
		}
		a := accepted.Authority
		if !reflect.DeepEqual(a, in.Authority) || in.Settings.Issuer != a.Creator.Issuer || app.RecorderPolicyScopeDigest(a.PolicyUID, record.IntentVersion, policySource(policy).CollectionDigest, in.Policy, a.NamespaceUID, a.WorkloadUID, a.Delegation, a.Owners, a.Actions, a.Limits) != a.ScopeDigest {
			return value.ErrChanged
		}
		step = "projection"
		projection, err := automationProjection(call, q, permissions, s.installation, a, in.Target.Target())
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(call)
		if err != nil {
			return err
		}
		purpose := authorization.PolicyRenew
		if in.Initial {
			purpose = authorization.PolicyArm
		}
		step = "eligibility"
		eligible := authorization.EvaluatePolicy(a, projection, authorization.PolicyUse{PolicyUID: a.PolicyUID, ScopeDigest: a.ScopeDigest, Target: in.Target.Target(), Purpose: purpose}, now.Time)
		if !eligible.Eligible {
			return value.ErrDenied
		}
		narrow("accepted", accepted.FreshUntil)
		narrow("eligibility", eligible.ValidUntil)
		var originalAudience []artifact.AudienceAssignment
		var originalAudienceDigest artifact.Digest
		audienceReason := ""
		if in.Initial {
			var audienceUntil time.Time
			originalAudience, audienceUntil, audienceReason = authorization.PolicyDefaultAudience(projection.Permissions, now.Time)
			if audienceReason == "" {
				var digestErr error
				originalAudienceDigest, digestErr = compiler.SourceAudienceDigest(originalAudience)
				if digestErr != nil {
					audienceReason = "AudienceUnavailable"
				} else {
					narrow("audience", audienceUntil)
				}
			}
		}

		step = "grant"
		hard := a.NotAfter
		// An ordinary require-all review is checked without consuming a raw-byte
		// grant pool. A changed attachment cannot refill this source's input credit.
		if in.Settings.RequireRecordingApproval || policy.AuthoredGrantRef != "" {
			if !policy.GrantAttachmentID.Valid {
				return value.ErrDenied
			}
			attachment, err := q.ReadPolicyGrantAttachment(call, custodydb.ReadPolicyGrantAttachmentParams{RootID: id(s.root), ID: policy.GrantAttachmentID})
			if err != nil {
				return err
			}
			if attachment.AcceptanceID != policy.ActiveID {
				return value.ErrChanged
			}
			row, err := q.ReadGrantForUpdate(call, custodydb.ReadGrantForUpdateParams{RootID: id(s.root), ID: attachment.GrantID})
			if err != nil {
				return err
			}
			g, err := grantFromRow(row)
			if err != nil {
				return err
			}
			if row.PolicyAcceptanceID != policy.ActiveID || g.Policy == nil || g.Policy.Observation != nil || g.Policy.RecipeDigest != in.Policy.Recorder.RecipeDigest || authorization.CheckPolicyGrantAttachment(g, a, policy.AuthoredGrantRef, now.Time) != nil {
				return value.ErrDenied
			}
			hard = identity.Earlier(hard, identity.Earlier(g.PolicyNotAfter, g.ExpiresAt))
		}
		step = "storage"
		storage, err := q.ObserveContextStorage(call, custodydb.ObserveContextStorageParams{RootID: id(s.root), ClusterID: id(a.ClusterID), NamespaceUid: a.NamespaceUID, WorkloadUid: a.WorkloadUID})
		if err != nil {
			return err
		}
		binding, err := q.FindContextControlBinding(call, custodydb.FindContextControlBindingParams{RootID: id(s.root), AllocationID: storage.AllocationID})
		if err != nil {
			return err
		}
		pool, allocation, err := lockAllocation(call, q, uid(storage.AllocationID))
		if err != nil {
			return err
		}
		controlPool, err := q.LockContextControlPool(call, id(s.root))
		if err != nil {
			return err
		}
		account, err := q.LockContextControlAccount(call, custodydb.LockContextControlAccountParams{RootID: id(s.root), AllocationID: allocation.ID})
		if err != nil {
			return err
		}
		step = "resources"
		resource, err := q.ReadPolicySourceResourceSelection(call, custodydb.ReadPolicySourceResourceSelectionParams{RootID: id(s.root), AllocationID: allocation.ID})
		if err != nil {
			return err
		}
		limits, resourceDigest, err := sourceResources(resource, a.ClusterID, now.Time)
		if err != nil {
			return err
		}
		out.Resources = limits

		rate := in.BytesPerSecond
		slots := in.SourceSlots
		if limits.Node.MaxActiveSources > 0 {
			slots = min(slots, limits.Node.MaxActiveSources)
		}
		lower := func(total, parts int64) {
			if total > 0 {
				rate = min(rate, total/parts)
			}
		}
		lower(limits.Node.InputBytesPerSecond, slots)
		lower(limits.Node.InputBurstBytes, slots)
		workloadSlots := int64(in.Policy.ObservedPods)
		if limits.Workload.MaxActiveSources > 0 {
			workloadSlots = min(workloadSlots, limits.Workload.MaxActiveSources)
		}
		lower(limits.Workload.InputBytesPerSecond, workloadSlots)
		lower(limits.Workload.InputBurstBytes, workloadSlots)
		if rate < 1 {
			return value.ErrCapacity
		}

		narrow("binding", binding.FreshUntil.Time)
		narrow("resources", resource.FreshUntil.Time)
		coverageUntil := identity.Earlier(pool.ValidUntil.Time, identity.Earlier(allocation.ValidUntil.Time, identity.Earlier(controlPool.ValidUntil.Time, account.ValidUntil.Time)))
		narrow("coverage", coverageUntil)
		// Commit uses the same narrowed original authority as the final
		// checks. No slow COMMIT can outlive a shorter accepted observation.
		cutoffDone = make(chan struct{})
		done := cutoffDone
		cutoff = time.AfterFunc(time.Until(until), func() { end(); close(done) })
		check := func() error {
			n, err := q.CurrentTime(call)
			if err != nil {
				return err
			}
			if call.Err() != nil || !sourceCheckCurrent(in, n.Time) || !n.Time.Before(until) || !n.Time.Before(hard) || !sourceResourceCurrent(resource, n.Time) || !identity.Fresh(binding.ObservedAt.Time, binding.FreshUntil.Time, n.Time, 30*time.Second) ||
				binding.ClusterID != id(a.ClusterID) || binding.NamespaceUid != a.NamespaceUID || binding.WorkloadUid != a.WorkloadUID || binding.AllocationID != allocation.ID || allocation.ServiceClass != "context" || allocation.Paused || pool.Paused || !n.Time.Before(storage.CapacityUntil.Time) || !controlPool.Configured || !account.Configured || controlPool.Paused || account.Paused || account.ChargedFull > account.FullLimit || account.ChargedReplay > account.ReplayLimit {
				return value.ErrChanged
			}
			if err = s.guards.Recovery.check(call, q, trust, s.root, in.Recovery); err != nil {
				return err
			}
			return s.guards.Retention.check(call, q, topology, in.Retention.Proof, in.Target.Target())
		}
		step = "check"
		if err = check(); err != nil {
			return err
		}
		step = "insert"
		row, err := q.ReadPolicyRecordingSource(call, custodydb.ReadPolicyRecordingSourceParams{RootID: id(s.root), ID: id(in.SourceID)})
		first := errors.Is(err, pgx.ErrNoRows)
		if err != nil && !first {
			return err
		}
		if first {
			if !in.Initial {
				return value.ErrConflict
			}
			// Original policy lock serializes the logical slot; account lock
			// serializes aggregate workload count/rate/burst across policies.
			if _, err = q.FindPolicyRecordingSource(call, custodydb.FindPolicyRecordingSourceParams{RootID: id(s.root), PolicyUid: a.PolicyUID, ActionID: in.Policy.Recorder.Action.ID, PodUid: in.Node.PodUID}); err == nil {
				return value.ErrConflict
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			count, err := q.CountPolicyRecordingSources(call, custodydb.CountPolicyRecordingSourcesParams{RootID: id(s.root), AllocationID: allocation.ID})
			if err != nil {
				return err
			}
			if limits.Workload.MaxActiveSources > 0 && count.SourceCount >= limits.Workload.MaxActiveSources || limits.Workload.InputBytesPerSecond > 0 && rate > limits.Workload.InputBytesPerSecond-count.InputRate || limits.Workload.InputBurstBytes > 0 && rate > limits.Workload.InputBurstBytes-count.InputRate {
				return value.ErrCapacity
			}
			budget, err := q.ReadPolicyAcceptance(call, custodydb.ReadPolicyAcceptanceParams{RootID: id(s.root), ID: policy.ActiveID})
			if err != nil {
				return err
			}
			if audienceReason != "" || len(originalAudience) == 0 {
				return value.ErrDenied
			}
			initialCredit := min(in.InitialCredit, a.Limits.MaxObservedBytes-budget.ObservedBytesSpent)
			if initialCredit < 1 {
				return value.ErrCapacity
			}
			n, err := q.SpendPolicySourceObservedBytes(call, custodydb.SpendPolicySourceObservedBytesParams{RootID: id(s.root), ID: policy.ActiveID, Bytes: initialCredit})
			if err != nil {
				return err
			}
			if n != 1 {
				return value.ErrCapacity
			}
			now, err = q.CurrentTime(call)
			if err != nil {
				return err
			}
			b := collector.SourceBinding{RootID: s.root, PolicyUID: a.PolicyUID, AcceptanceID: record.ID, SourceID: in.SourceID, Fence: in.Fence, ActionID: in.Policy.Recorder.Action.ID, PodUID: in.Node.PodUID, NodeUID: in.Node.NodeUID, BootID: in.Node.BootID, CollectorPodUID: in.Node.CollectorPodUID, CollectorEpoch: in.Node.CollectorEpoch, Scope: [32]byte(a.ScopeDigest), ExpectationDigest: [32]byte(in.Policy.Recorder.Digest), ResourceDigest: resourceDigest, AudienceDigest: [32]byte(originalAudienceDigest)}
			if in.Policy.Recorder.Filter != nil {
				b.ProgramDigest = [32]byte(compiler.FilterProgramDigest(in.Policy.Recorder.Filter.Program))
			}
			if !b.Valid() {
				return value.ErrInvalid
			}
			raw, _ := json.Marshal(b)
			originalTarget := targets.SourceSnapshotTarget{Request: in.Target.Request, Pin: in.Target.Pin, NodeUID: b.NodeUID, BootID: b.BootID, CollectorPodUID: b.CollectorPodUID, CollectorEpoch: b.CollectorEpoch, SourceID: b.SourceID, Fence: b.Fence, BindingDigest: deliveryapp.SourceBindingDigest(b)}
			if !originalTarget.Valid() {
				return value.ErrInvalid
			}
			rawAudience, audienceErr := json.Marshal(originalAudience)
			rawTarget, targetErr := json.Marshal(originalTarget)
			if audienceErr != nil || targetErr != nil {
				return value.ErrInvalid
			}

			row, err = q.InsertPolicyRecordingSource(call, custodydb.InsertPolicyRecordingSourceParams{RootID: id(s.root), ID: id(in.SourceID), Fence: id(in.Fence), PolicyUid: a.PolicyUID, AcceptanceID: policy.ActiveID, ActionID: b.ActionID, ClusterID: id(a.ClusterID), NamespaceUid: a.NamespaceUID, WorkloadUid: a.WorkloadUID, PodUid: b.PodUID, AllocationID: allocation.ID, BindingJson: raw, StartedAt: ts(now.Time), HardUntil: ts(hard), StartBy: ts(identity.Earlier(until, now.Time.Add(5*time.Second))), InitialLeafUntil: ts(identity.Earlier(hard, identity.Earlier(coverageUntil, now.Time.Add(collector.SourceLeafLifetime)))), InitialCredit: initialCredit, Credit: initialCredit, BytesPerSecond: rate, SourceAudienceJson: rawAudience, SourceAudienceDigest: originalAudienceDigest[:], SourceTargetJson: rawTarget})
			if err != nil {
				return err
			}
		} else {
			if row.EndedAt.Valid || row.SlotReleasedAt.Valid || row.AcceptanceID != policy.ActiveID || row.Fence != id(in.Fence) || row.AllocationID != allocation.ID || row.PodUid != in.Node.PodUID || row.BytesPerSecond > rate {
				return value.ErrConflict
			}
			if in.Initial {
				// SourceID/fence and immutable binding identify this passive
				// replay. The original server-clamped credit is returned;
				// a different requested tranche cannot alter it.
			} else {
				if row.Credit < in.ExpectedCredit {
					return value.ErrConflict
				}
				// A stale expected credit cannot apply another increment.
				// Existing prepaid credit can renew even with parent remaining=0.
				if row.Credit == in.ExpectedCredit && in.AdditionalCredit > 0 {
					budget, err := q.ReadPolicyAcceptance(call, custodydb.ReadPolicyAcceptanceParams{RootID: id(s.root), ID: policy.ActiveID})
					if err != nil {
						return err
					}
					delta := min(in.AdditionalCredit, a.Limits.MaxObservedBytes-budget.ObservedBytesSpent)
					if delta < 0 {
						return value.ErrChanged
					}
					if delta > 0 {
						n, err := q.SpendPolicySourceObservedBytes(call, custodydb.SpendPolicySourceObservedBytesParams{RootID: id(s.root), ID: policy.ActiveID, Bytes: delta})
						if err != nil {
							return err
						}
						if n != 1 {
							return value.ErrCapacity
						}
						row, err = q.IncreasePolicyRecordingSourceCredit(call, custodydb.IncreasePolicyRecordingSourceCreditParams{RootID: id(s.root), ID: row.ID, ExpectedCredit: row.Credit, AdditionalCredit: delta})
						if err != nil {
							return err
						}
					}
				}
			}
		}
		state, err := policySourceState(row)
		if err != nil {
			return err
		}
		b := state.Binding
		if b.PolicyUID != a.PolicyUID || b.ActionID != in.Policy.Recorder.Action.ID || b.Scope != [32]byte(a.ScopeDigest) || b.ExpectationDigest != [32]byte(in.Policy.Recorder.Digest) || b.ResourceDigest != resourceDigest || b.NodeUID != in.Node.NodeUID || b.BootID != in.Node.BootID || b.CollectorPodUID != in.Node.CollectorPodUID || b.CollectorEpoch != in.Node.CollectorEpoch {
			return value.ErrChanged
		}
		now, err = q.CurrentTime(call)
		if err != nil {
			return err
		}
		issued := now.Time
		if in.Initial {
			issued = state.StartedAt
		}
		p := collector.SourcePermit{Binding: b, StartedAt: state.StartedAt, HardUntil: state.HardUntil, StartBy: state.StartBy, IssuedAt: issued, DispatchUntil: identity.Earlier(until, issued.Add(5*time.Second)), LeafUntil: identity.Earlier(state.HardUntil, identity.Earlier(hard, identity.Earlier(coverageUntil, issued.Add(collector.SourceLeafLifetime)))), Credit: state.Credit, BytesPerSecond: state.BytesPerSecond}
		if in.Initial {
			// Replay returns the immutable original first leaf/start window;
			// fresh authority may refuse it, never rewrite that receipt.
			p.DispatchUntil = state.StartBy
			p.LeafUntil = state.InitialLeafUntil
			p.Credit = state.InitialCredit
			if p.LeafUntil.After(hard) || p.LeafUntil.After(coverageUntil) {
				return value.ErrChanged
			}
		}
		step = "permit"
		if !p.Dispatchable(now.Time) {
			return value.ErrUnavailable
		}
		out.Permit, out.First = p, first
		step = "final-check"
		return check()
	})
	if err != nil {
		if call.Err() != nil {
			step += "-late-" + bound + "-" + sourceBudgetBucket(until.Sub(entered))
		}
		return app.PolicySourceAdmission{}, app.StagedSourceError("admit-"+step, captureError(err))
	}
	if call.Err() != nil || !out.Permit.Dispatchable(time.Now()) {
		return app.PolicySourceAdmission{}, app.StagedSourceError("admit-committed-late", value.ErrUnavailable)
	}
	return out, nil
}

// Migration 73/ADR-200 gives the protected accepted SQL row a 30s lifetime.
// Its original five-second acceptance payload is validated at its original
// observation instant; it is not a fresh caller receipt or a renewed proof.
func sourceResourceCurrent(row custodydb.ReadPolicySourceResourceSelectionRow, now time.Time) bool {
	return !row.Suspended && identity.Fresh(row.ObservedAt.Time, row.FreshUntil.Time, now, 30*time.Second)
}

func sourceResources(row custodydb.ReadPolicySourceResourceSelectionRow, cluster string, now time.Time) (collector.SourceResources, [32]byte, error) {
	var zero collector.SourceResources
	var observation capacity.CapacitySourceObservation
	if !sourceResourceCurrent(row, now) || row.AcceptedRevision < 1 || len(row.AcceptedDigest) != 32 || json.Unmarshal(row.AcceptedSnapshot, &observation) != nil || !observation.Valid(observation.Snapshot.ObservedAt) || !bytes.Equal(observation.Digest[:], row.AcceptedDigest) {
		return zero, [32]byte{}, value.ErrChanged
	}
	for _, policy := range observation.Snapshot.Policies {
		if policy.Resource.UID != row.PolicyUid {
			continue
		}
		if policy.Resource.Deleting || policy.Scope == nil || policy.Scope.ClusterID != cluster || policy.Budget == nil {
			return zero, [32]byte{}, value.ErrChanged
		}
		limits := collector.SourceResources{PolicyUID: policy.Resource.UID}
		if policy.SourceResources != nil {
			limits.Node = policy.SourceResources.Node
			limits.Workload = policy.SourceResources.Workload
		}
		return limits, deliveryapp.SourceResourcesDigest(limits), nil
	}
	return zero, [32]byte{}, value.ErrChanged
}

func policySourceState(row custodydb.PolicyRecordingSource) (app.PolicySourceState, error) {
	var b collector.SourceBinding
	if len(row.BindingJson) > 8192 || json.Unmarshal(row.BindingJson, &b) != nil || !b.Valid() || b.RootID != uid(row.RootID) || b.SourceID != uid(row.ID) || b.Fence != uid(row.Fence) || b.AcceptanceID != uid(row.AcceptanceID) || b.PolicyUID != row.PolicyUid || b.ActionID != row.ActionID || b.PodUID != row.PodUid {
		return app.PolicySourceState{}, value.ErrChanged
	}
	source := app.PolicySourceState{Binding: b, ClusterID: uid(row.ClusterID), NamespaceUID: row.NamespaceUid, WorkloadUID: row.WorkloadUid, StartedAt: row.StartedAt.Time, HardUntil: row.HardUntil.Time, StartBy: row.StartBy.Time, InitialLeafUntil: row.InitialLeafUntil.Time, InitialCredit: row.InitialCredit, Credit: row.Credit, BytesPerSecond: row.BytesPerSecond, EndedAt: row.EndedAt.Time}
	if err := sourceOriginalProvenance(row, &source); err != nil {
		return app.PolicySourceState{}, err
	}
	return source, nil
}

func (s *PolicySources) ListSources(ctx context.Context, policy string) ([]app.PolicySourceState, error) {
	if s == nil || !identity.Text(policy, 128) {
		return nil, value.ErrInvalid
	}
	var out []app.PolicySourceState
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = nil
		rows, err := q.ListPolicyRecordingSources(ctx, custodydb.ListPolicyRecordingSourcesParams{RootID: id(s.root), PolicyUid: policy})
		if err != nil {
			return err
		}
		if len(rows) > 1024 {
			return value.ErrCapacity
		}
		for _, row := range rows {
			state, err := policySourceState(row)
			if err != nil {
				return err
			}
			out = append(out, state)
		}
		return nil
	})
	return out, captureError(err)
}
func (s *PolicySources) EndSource(ctx context.Context, source string) error {
	if s == nil || !authorization.UUID(source) {
		return value.ErrInvalid
	}
	return captureError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		if _, err := q.EndPolicyRecordingSource(ctx, custodydb.EndPolicyRecordingSourceParams{RootID: id(s.root), ID: id(source)}); err != nil {
			return err
		}
		_, err := q.ReleaseEndedPolicySourceSlots(ctx, id(s.root))
		return err
	}))
}

// SweepSources only fences already-known inactive/replaced or hard-expired
// sources. Stale observations never fabricate a negative. Bounded pages run on
// the existing policy cycle; ended identities and input spend remain retained.
func (s *PolicySources) SweepSources(ctx context.Context) ([]app.PolicySourceState, error) {
	if s == nil {
		return nil, value.ErrInvalid
	}
	var out []app.PolicySourceState
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = nil
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		ended, err := q.EndInactivePolicyRecordingSources(ctx, id(s.root))
		if err != nil {
			return err
		}
		for _, row := range ended {
			state, err := policySourceState(row)
			if err != nil {
				return err
			}
			out = append(out, state)
		}
		_, err = q.ReleaseEndedPolicySourceSlots(ctx, id(s.root))
		return err
	})
	return out, captureError(err)
}

// sourceBudgetBucket is a bounded label for the admission time budget.
func sourceBudgetBucket(d time.Duration) string {
	switch {
	case d <= 0:
		return "expired"
	case d < time.Second:
		return "lt1s"
	case d < 3*time.Second:
		return "lt3s"
	}
	return "ge3s"
}
