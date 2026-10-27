package configuration

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// BindingJournal processes every ownership transition before the next one. It
// does not activate configuration: protected bootstrap, guard qualification and
// PermissionStore acceptance are still required. Use one serial coordinator.
type BindingJournal struct {
	cluster         string
	control         value.NamespaceRef
	byUID           map[string]value.Binding
	names           map[string]string
	cursor          string
	observed, until time.Time
	accepted        bool
	poisoned        bool
	pending         *value.PermissionBatch
	sequence        int64
	acceptedFence   value.PermissionFence
	initial         value.PermissionInitialization
}

func cloneBinding(b value.Binding) value.Binding {
	b.Subjects = slices.Clone(b.Subjects)
	b.Roles = slices.Clone(b.Roles)
	b.Scope.Workloads = slices.Clone(b.Scope.Workloads)
	if b.Automation != nil {
		a := *b.Automation
		a.AllowedActions = slices.Clone(a.AllowedActions)
		b.Automation = &a
	}
	return b
}
func journalIdentity(b value.Binding, cluster string, control value.NamespaceRef) bool {
	r := b.Resource
	return r.ClusterID == cluster && r.Namespace == control.Name && r.NamespaceUID == control.UID && r.Kind == "AccessBinding" && identity.Text(r.Name, 253) && identity.Text(r.UID, 64) && identity.Text(r.ResourceVersion, 128) && r.Generation > 0 && r.Generation <= 2147483647 && r.SpecDigest != (artifact.Digest{})
}
func NewBindingJournal(s value.Snapshot, now time.Time) (*BindingJournal, error) {
	if !authorization.UUID(s.ClusterID) || !identity.Text(s.ControlNamespace.Name, 63) || !identity.Text(s.ControlNamespace.UID, 64) || !identity.Text(s.BindingResourceVersion, 128) || !identity.Fresh(s.ObservedAt, s.FreshUntil, now, 5*time.Second) || len(s.Bindings) > 1024 {
		return nil, value.ErrInvalid
	}
	j := &BindingJournal{cluster: s.ClusterID, control: s.ControlNamespace, cursor: s.BindingResourceVersion, observed: s.ObservedAt, until: s.FreshUntil, byUID: map[string]value.Binding{}, names: map[string]string{}}
	for _, b := range s.Bindings {
		if !journalIdentity(b, j.cluster, j.control) || j.names[b.Resource.Name] != "" {
			return nil, value.ErrInvalid
		}
		if _, exists := j.byUID[b.Resource.UID]; exists {
			return nil, value.ErrInvalid
		}
		j.byUID[b.Resource.UID] = cloneBinding(b)
		j.names[b.Resource.Name] = b.Resource.UID
	}
	j.initial = value.PermissionInitialization{ClusterID: s.ClusterID, Control: s.ControlNamespace, BindingsDigest: InitialBindingDigest(s), BindingCount: len(s.Bindings)}
	return j, nil
}

// SetInitialReview attaches only a separately read protected installation
// review. Runtime composition must qualify that reader independently of sources.
func (j *BindingJournal) SetInitialReview(r value.BootstrapReview, now time.Time) error {
	if j.pending != nil || j.sequence != 0 || j.initial.BindingCount == 0 {
		return value.ErrChanged
	}
	p := j.initial
	p.Review = &r
	if !p.Valid(now) {
		return value.ErrDenied
	}
	j.initial = p
	return nil
}
func (j *BindingJournal) Cursor() string { return j.cursor }

// Constrain preserves the original list deadline while also bounding it by the
// guard/review observation. It never makes an old source observation fresh.
func (j *BindingJournal) Constrain(until time.Time) error {
	if j.pending != nil || !until.After(j.observed) {
		return value.ErrChanged
	}
	j.until = identity.Earlier(j.until, until)
	return nil
}
func (j *BindingJournal) Apply(e value.BindingEvent) error {
	if j.poisoned || !j.accepted || j.pending != nil {
		return value.ErrChanged
	}
	fail := func() error { j.poisoned = true; return value.ErrChanged }
	if !identity.Text(e.ResourceVersion, 128) {
		return fail()
	}
	if e.Type == "BOOKMARK" {
		if e.Binding != nil {
			return fail()
		}
		j.cursor = e.ResourceVersion
		return nil
	}
	if e.Binding == nil || !journalIdentity(*e.Binding, j.cluster, j.control) || e.Binding.Resource.ResourceVersion != e.ResourceVersion {
		return fail()
	}
	b := *e.Binding
	old, exists := j.byUID[b.Resource.UID]
	switch e.Type {
	case "ADDED":
		if exists || j.names[b.Resource.Name] != "" || len(j.byUID) >= 1024 {
			return fail()
		}
		j.byUID[b.Resource.UID] = cloneBinding(b)
		j.names[b.Resource.Name] = b.Resource.UID
	case "MODIFIED", "DELETED":
		if !exists || old.Resource.Name != b.Resource.Name || b.Resource.Generation < old.Resource.Generation || b.Resource.Generation > old.Resource.Generation+1 || (b.Resource.Generation == old.Resource.Generation && b.Resource.SpecDigest != old.Resource.SpecDigest) || (old.Resource.Deleting && !b.Resource.Deleting && e.Type != "DELETED") {
			return fail()
		}
		if b.Resource.ResourceVersion == old.Resource.ResourceVersion {
			if !equalBinding(old, b) || e.Type == "DELETED" {
				return fail()
			}
			return nil // Duplicate delivery does not renew freshness.
		}
		if e.Type == "DELETED" {
			delete(j.byUID, b.Resource.UID)
			delete(j.names, b.Resource.Name)
		} else {
			j.byUID[b.Resource.UID] = cloneBinding(b)
		}
	default:
		return fail()
	}
	j.cursor = e.ResourceVersion
	// Require the coordinator to commit this transition before applying another.
	j.accepted = false
	return nil
}
func equalBinding(a, b value.Binding) bool {
	// SpecDigest binds the validated source; values remain checked as defense
	// against an accidentally mutated in-process DTO.
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// Confirm refreshes completeness only when a current full LIST exactly agrees
// with the processed watch state. A bookmark or a successful unrelated GET is
// not evidence that the complete deny set is fresh. Mismatch means catch up or
// start a new baseline; never replace the journal and claim continuity.
func (j *BindingJournal) Confirm(s value.Snapshot, now time.Time) error {
	if j.poisoned || j.pending != nil || !j.accepted || s.ClusterID != j.cluster || s.ControlNamespace != j.control || !identity.Fresh(s.ObservedAt, s.FreshUntil, now, 5*time.Second) || !s.ObservedAt.After(j.observed) || len(s.Bindings) != len(j.byUID) {
		return value.ErrChanged
	}
	seen := map[string]bool{}
	for _, b := range s.Bindings {
		old, exists := j.byUID[b.Resource.UID]
		if !exists || seen[b.Resource.UID] || !equalBinding(old, b) {
			return value.ErrChanged
		}
		seen[b.Resource.UID] = true
	}
	j.observed = s.ObservedAt
	j.until = s.FreshUntil
	return nil
}
func cloneBatch(b value.PermissionBatch) value.PermissionBatch {
	if b.Initial != nil {
		p := *b.Initial
		if p.Review != nil {
			r := *p.Review
			p.Review = &r
		}
		b.Initial = &p
	}
	b.UnavailableSources = slices.Clone(b.UnavailableSources)
	b.ReviewSources = slices.Clone(b.ReviewSources)
	b.Bases = slices.Clone(b.Bases)
	for i := range b.Bases {
		p := &b.Bases[i]
		p.Subjects = slices.Clone(p.Subjects)
		p.Roles = slices.Clone(p.Roles)
		p.Scope.Workloads = slices.Clone(p.Scope.Workloads)
		if p.Automation != nil {
			a := *p.Automation
			a.AllowedActions = slices.Clone(a.AllowedActions)
			p.Automation = &a
		}
	}
	return b
}

// Ready reports whether a batch can be prepared at now without failing: the
// last transition is accepted and the complete binding list is still current.
func (j *BindingJournal) Ready(now time.Time) bool {
	return !j.poisoned && j.pending == nil && j.accepted && identity.Fresh(j.observed, j.until, now, 5*time.Second)
}

// Budget counts the bases and assignment rows that the explicit bindings
// would add to a batch prepared at now.
func (j *BindingJournal) Budget(now time.Time) (bases, rows int) {
	for _, b := range j.byUID {
		if (b.Resource.Deleting && b.Effect == "Allow") || (!b.NotAfter.IsZero() && !now.Before(b.NotAfter)) {
			continue
		}
		bases++
		rows += len(b.Subjects) * len(b.Roles)
	}
	return bases, rows
}

// Prepare builds the next batch from the processed bindings and the
// separately derived inheritance (ADR-242).
func (j *BindingJournal) Prepare(f value.PermissionFence, request string, now time.Time, inherited Inheritance) (value.PermissionBatch, error) {
	if j.poisoned || !authorization.UUID(request) {
		return value.PermissionBatch{}, value.ErrChanged
	}
	if j.pending != nil {
		if j.pending.RequestID != request || j.pending.RootID != f.RootID || j.pending.Epoch != f.Epoch || j.pending.TrustDigest != f.TrustDigest || j.pending.ExpectedSequence != f.Sequence {
			return value.PermissionBatch{}, value.ErrChanged
		}
		return cloneBatch(*j.pending), nil
	}
	if !identity.Fresh(j.observed, j.until, now, 5*time.Second) {
		return value.PermissionBatch{}, value.ErrChanged
	}
	if j.sequence != 0 && (f.Sequence != j.sequence || f.RootID != j.acceptedFence.RootID || f.Epoch != j.acceptedFence.Epoch || f.TrustDigest != j.acceptedFence.TrustDigest) {
		return value.PermissionBatch{}, value.ErrChanged
	}
	bindings := make([]value.Binding, 0, len(j.byUID))
	for _, b := range j.byUID {
		bindings = append(bindings, cloneBinding(b))
	}
	slices.SortFunc(bindings, func(a, b value.Binding) int { return cmp.Compare(a.Resource.UID, b.Resource.UID) })
	// The input digest covers the explicit bindings and the derived
	// inheritance; continuity flags never change what is accepted.
	derived := inherited
	derived.Bases = slices.Clone(inherited.Bases)
	for n := range derived.Bases {
		derived.Bases[n].Continuous = false
	}
	encoded, err := json.Marshal(struct {
		Bindings  []value.Binding
		Inherited Inheritance `json:",omitzero"`
	}{bindings, derived})
	if err != nil || len(encoded) > 8<<20 {
		return value.PermissionBatch{}, value.ErrLimit
	}
	batch := value.PermissionBatch{RootID: f.RootID, Epoch: f.Epoch, RequestID: request, ExpectedSequence: f.Sequence, TrustDigest: f.TrustDigest, InputDigest: artifact.Digest(sha256.Sum256(encoded)), ObservedAt: now, FreshUntil: j.until}
	if !f.Initialized {
		p := j.initial
		batch.Initial = &p
		if !p.Valid(now) {
			return value.PermissionBatch{}, value.ErrDenied
		}
		if p.Review != nil {
			batch.FreshUntil = identity.Earlier(batch.FreshUntil, identity.Earlier(p.Review.FreshUntil, p.Review.ExpiresAt))
		}
	}
	for _, b := range bindings {
		if (b.Resource.Deleting && b.Effect == "Allow") || (!b.NotAfter.IsZero() && !now.Before(b.NotAfter)) {
			continue
		}
		p := value.PermissionBasis{Resource: b.Resource, Scope: b.Scope, Effect: b.Effect, Subjects: b.Subjects, Roles: b.Roles, NotAfter: b.NotAfter, Automation: b.Automation, Continuous: j.sequence > 0}
		p.ScopeDigest = PermissionScopeDigest(p)
		batch.Bases = append(batch.Bases, p)
	}
	batch.Bases = append(batch.Bases, inherited.Bases...)
	batch.UnavailableSources = slices.Clone(inherited.UnavailableSources)
	batch.SourcesUnavailable = inherited.SourcesUnavailable
	batch.Namespaces = inherited.Namespaces
	batch.RemoteNamespaces = slices.Clone(inherited.RemoteNamespaces)
	batch.Workloads = slices.Clone(inherited.Workloads)
	batch.ReviewSources = slices.Clone(inherited.ReviewSources)
	if err = batch.Validate(now); err != nil {
		return value.PermissionBatch{}, err
	}
	j.pending = &batch
	return cloneBatch(batch), nil
}

// Accepted may be called only after a successful durable acceptance, including
// resolution of an ambiguous COMMIT by the original request. It rejects an
// acknowledgement for another stream, generation or event.
func (j *BindingJournal) Accepted(r value.PermissionAcceptance) error {
	if j.pending == nil || r.RootID != j.pending.RootID || r.Epoch != j.pending.Epoch || r.TrustDigest != j.pending.TrustDigest || r.Sequence != j.pending.ExpectedSequence+1 || r.AuditID != j.pending.RequestID {
		return value.ErrChanged
	}
	j.sequence = r.Sequence
	j.acceptedFence = r.PermissionFence
	j.pending = nil
	j.accepted = true
	return nil
}

// Refreshed follows only a successful identical-projection refresh. It cannot
// acknowledge a changed watch transition or initialize an unaccepted baseline.
func (j *BindingJournal) Refreshed(request string) error {
	if j.pending == nil || !j.accepted || j.sequence == 0 || j.pending.RequestID != request || j.pending.ExpectedSequence != j.sequence {
		return value.ErrChanged
	}
	j.pending = nil
	return nil
}
