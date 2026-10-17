package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// Private protected installation configuration, not certificate-request fields.
// SQL keeps aggregate reservations across all retained peers under this root.
type ConnectorIdentityBacking struct {
	AccountVersion                                    string
	AccountLimit, RecordsPerAccount, RetainedSeconds  int64
	ProfileLimit, SourceTransitionLimit               int64
	SourceBackupReservedBytes, SourceWALReservedBytes int64
	Policy                                            audit.OperationLifecyclePolicy
}

func (b ConnectorIdentityBacking) Valid() bool {
	p := b.Policy
	if !p.Valid() || p.Lane != "identity" || p.OverdueTerminal != audit.OperationOverdueTerminal || p.History == nil || (p.History.Layout != audit.ConnectorOperationHistoryLayout && p.History.Layout != audit.ConnectorRetirementHistoryLayout) || !identity.Text(b.AccountVersion, 64) || b.AccountLimit < 1 || b.AccountLimit > 4096 || b.RecordsPerAccount < 2 || b.RecordsPerAccount > 1000000 || b.ProfileLimit < 1 || b.ProfileLimit > b.AccountLimit || b.SourceTransitionLimit < b.ProfileLimit || b.SourceTransitionLimit > 1000000 || b.RetainedSeconds < 60 || b.RetainedSeconds > 316224000 || p.MetadataSlots < b.AccountLimit*b.RecordsPerAccount {
		return false
	}
	q := p.History
	// These are additional source/profile reservations; pair slots do not also
	// pay for an uncharged pending administrator revision.
	rows := b.ProfileLimit + 1
	if q.Layout == audit.ConnectorRetirementHistoryLayout {
		// A ticket can retain its immutable cohort/ID after its unused pair is
		// positively closed, or after an admitted pair enters minimized history.
		// Its row has separate original source backing, never a borrowed pair
		// charge or an audit FK retained past that pair's original purge date.
		// Validated factors are bounded by 4096 and 1000001, so this cannot wrap.
		rows += b.ProfileLimit * (b.SourceTransitionLimit + 1)
	}
	transitions := 2 * b.SourceTransitionLimit
	if q.Layout == audit.ConnectorRetirementHistoryLayout {
		// A positively closed unused pair can release its reservation while its
		// original ticket tombstone must still be deleted later. Independent source
		// WAL therefore prepays all ticket transitions, not only initial staging.
		transitions += ConnectorRetirementTicketTransitions * b.ProfileLimit * (b.SourceTransitionLimit + 1)
	}
	return b.SourceBackupReservedBytes > 0 && b.SourceWALReservedBytes > 0 && b.SourceBackupReservedBytes/rows >= 2*q.MaximumRowFootprintBytes*q.BackupCopies && b.SourceWALReservedBytes/q.MaximumTransitionWALBytes/q.WALCopies >= transitions
}
func (b ConnectorIdentityBacking) Clone() ConnectorIdentityBacking {
	if b.Policy.History != nil {
		q := *b.Policy.History
		b.Policy.History = &q
	}
	return b
}

type ConnectorIdentityConfiguration struct {
	Source  value.ConnectorIdentitySource
	Backing ConnectorIdentityBacking
}

func (c ConnectorIdentityConfiguration) Valid(now time.Time) bool {
	return c.Source.Valid(now) && c.Source.Observation.Backing.Revision == c.Backing.Policy.BackingRevision && c.Backing.Valid() && c.Backing.Policy.RootID == c.Source.Observation.Profile.RootID && c.Backing.Policy.InstallationID == c.Source.Observation.Profile.Binding.InstallationID && c.Backing.SupportsDeployment(c.Source.Observation.Profile.Deployment) && now.Before(c.Backing.Policy.ValidUntil)
}
func (c ConnectorIdentityConfiguration) Clone() ConnectorIdentityConfiguration {
	c.Source.Observation.Profile = c.Source.Observation.Profile.Clone()
	c.Backing = c.Backing.Clone()
	return c
}

type ConnectorIdentityConfigurationReader interface {
	ReadConnectorIdentityConfiguration(context.Context) (ConnectorIdentityConfiguration, error)
}

// The installation accepts measured provider/SQL/history qualification outside
// this source. This immutable pin only checks that configuration consumes that
// exact accepted result. Constructing it or supplying its digest is not a test
// result, provisioning or resource reservation.
type ConnectorQualificationPin struct {
	InstallationID, StoreID, BackupProfileID string
	Qualification                            audit.OperationHistoryQualification
}

func (p ConnectorQualificationPin) Matches(c ConnectorIdentityConfiguration) bool {
	q := c.Backing.Policy
	return p.Qualification.Valid() && (p.Qualification.Layout == audit.ConnectorOperationHistoryLayout || p.Qualification.Layout == audit.ConnectorRetirementHistoryLayout) && p.InstallationID == q.InstallationID && p.StoreID == q.StoreID && p.BackupProfileID == q.BackupProfileID && q.History != nil && p.Qualification == *q.History
}

// Staging can only create an inactive candidate or record a monotonic source
// fence. It cannot accept the source, issue certificates, clear recovery or
// install a peer; first peer acceptance follows its closed intent audit.
type ConnectorIdentitySourceJournal interface {
	StageConnectorIdentity(context.Context, ConnectorIdentityConfiguration) error
	FenceConnectorIdentity(context.Context, value.PeerBinding, time.Time) error
}
type ConnectorIdentityObserver struct {
	Reader        ConnectorIdentityConfigurationReader
	Journal       ConnectorIdentitySourceJournal
	Qualification ConnectorQualificationPin
	Binding       value.PeerBinding
	Now           func() time.Time
	// Backing, when set, is the hub-decided backing the read configuration
	// must equal before anything is staged (ADR-193: a region never chooses
	// the root backing).
	Backing *ConnectorIdentityBacking
}

func (s ConnectorIdentityObserver) Observe(ctx context.Context) error {
	_, err := s.ObserveConfiguration(ctx)
	return err
}

// ObserveConfiguration stages the delegated configuration and returns it.
func (s ConnectorIdentityObserver) ObserveConfiguration(ctx context.Context) (ConnectorIdentityConfiguration, error) {
	var zero ConnectorIdentityConfiguration
	if ctx == nil || ctx.Err() != nil || s.Reader == nil || s.Journal == nil || s.Now == nil || !s.Binding.Valid() || s.Binding.Role != value.ConnectorPeer {
		return zero, value.ErrUnavailable
	}
	start := s.Now().UTC().Truncate(time.Microsecond)
	live, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	c, e := s.Reader.ReadConnectorIdentityConfiguration(live)
	if e != nil || !c.Valid(s.Now()) || c.Source.Observation.Profile.Binding != s.Binding || !s.Qualification.Matches(c) || live.Err() != nil || s.Backing != nil && !sameBacking(c.Backing, *s.Backing) {
		// Failure fencing is an independently bounded restrictive action and cannot
		// manufacture a later positive observation or acknowledge a candidate.
		stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.Journal.FenceConnectorIdentity(stop, s.Binding, start)
		return zero, value.ErrUnavailable
	}
	until := identity.Earlier(start.Add(5*time.Second), identity.Earlier(c.Source.Observation.FreshUntil, c.Backing.Policy.ValidUntil))
	bounded, cancel := context.WithDeadline(live, until)
	defer cancel()
	if !s.Now().Before(until) {
		return zero, value.ErrUnavailable
	}
	if e = s.Journal.StageConnectorIdentity(bounded, c.Clone()); e != nil {
		// A failed commit is not evidence that the accepted source stayed current.
		// This independently bounded restriction cannot clear SQL's stronger
		// known-mutation watermark or manufacture positive source freshness.
		stop, finish := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer finish()
		_ = s.Journal.FenceConnectorIdentity(stop, s.Binding, start)
		return zero, e
	}
	if bounded.Err() != nil || !s.Now().Before(until) {
		return zero, value.ErrUnavailable
	}
	return c.Clone(), nil
}

func sameBacking(a, b ConnectorIdentityBacking) bool {
	x, e := json.Marshal(a)
	if e != nil {
		return false
	}
	y, e := json.Marshal(b)
	return e == nil && bytes.Equal(x, y)
}

// ProcessRunSeconds fixes the process end before the original admission pair's
// purge window, including one minute for the last possible leaf/relay boundary.
// Neither a fresh observation nor a replacement process can extend that pair.
func (b ConnectorIdentityBacking) ProcessRunSeconds() int64 {
	return b.RetainedSeconds - 2*b.Policy.BackupHorizonSeconds - 3*b.Policy.CleanupBudgetSeconds - b.Policy.ProofWindowSeconds - 60
}
func (b ConnectorIdentityBacking) SupportsDeployment(d value.ConnectorDeployment) bool {
	return d.Valid() && b.supportsProcessLimits(d.ServingSlots, d.RetainedProcesses)
}

// SupportsProcessLimits checks a deployment shape before any regional source
// exists (ADR-193: the continuation refuses a backing that installer-cluster's
// fixed shape could not use).
func (b ConnectorIdentityBacking) SupportsProcessLimits(servingSlots, retainedProcesses int) bool {
	return b.supportsProcessLimits(servingSlots, retainedProcesses)
}

// Exact historical profile limits are retained by restrictive tickets. Checking
// their finite backing needs no invented controller names or current proof.
func (b ConnectorIdentityBacking) supportsProcessLimits(servingSlots, retainedProcesses int) bool {
	if !b.Valid() || servingSlots < 1 || servingSlots > 16 || retainedProcesses < servingSlots+1 || retainedProcesses > 256 {
		return false
	}
	run := b.ProcessRunSeconds()
	if run < 1800 {
		return false
	}
	// One serving generation, independently retained prior generations across the
	// accepted horizon, and one pending generation per serving slot plus one
	// process admit slot. SQL still enforces actual aggregate retained counts.
	retained := int64(servingSlots)*((b.RetainedSeconds+run-1)/run+1) + 1
	if int64(retainedProcesses) < retained {
		return false
	}
	// Each retained process has its admission pair and at most two provider tries
	// for each initial purpose. The finite 30-minute cadence is backed over the
	// full retention interval, including the one-minute early renewal overlap.
	epochs := (b.RetainedSeconds+1799)/1800 + 1
	required := 5*int64(retainedProcesses) + 4*int64(servingSlots)*epochs + b.SourceTransitionLimit
	if b.Policy.History.Layout == audit.ConnectorRetirementHistoryLayout {
		required += b.SourceTransitionLimit + 1
	}
	return b.RecordsPerAccount >= required
}

// CanRenew is a compatibility check, not source/audit acceptance. New physical
// capacity or a different backup/qualification requires separate acceptance.
func (next ConnectorIdentityBacking) CanRenew(previous ConnectorIdentityBacking) bool {
	return next.SameResources(previous) && next.Policy.BackingRevision == previous.Policy.BackingRevision+1 && next.Policy.ValidUntil.After(previous.Policy.ValidUntil)
}

// SameResources checks immutable qualification/allocation compatibility only.
// A current SQL acceptance, never this structural equality, selects a revision.
func (next ConnectorIdentityBacking) SameResources(previous ConnectorIdentityBacking) bool {
	if !next.Valid() || !previous.Valid() || *next.Policy.History != *previous.Policy.History {
		return false
	}
	a, b := next, previous
	a.Policy.History = nil
	b.Policy.History = nil
	a.Policy.BackingRevision = b.Policy.BackingRevision
	a.Policy.ValidUntil = b.Policy.ValidUntil
	a.Policy.PolicyID = b.Policy.PolicyID
	a.Policy.PolicyDigest = b.Policy.PolicyDigest
	return a == b
}
