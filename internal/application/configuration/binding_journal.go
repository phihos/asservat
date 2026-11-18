package configuration

import (
	"cmp"
	"encoding/json"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// BindingJournal processes every ownership transition before the next one. It
// does not activate configuration: protected bootstrap, guard qualification and
// PermissionStore acceptance are still required. Use one serial coordinator.
type BindingJournal struct {
	cluster         string
	byUID           map[string]value.Binding
	names           map[string]string
	cursor          string
	observed, until time.Time
	accepted        bool
	poisoned        bool
	pending         *value.PermissionBatch
	sequence        int64
	acceptedFence   value.PermissionFence
	// Issuer is the installation's issuer for subjects that omit one.
	Issuer string
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

// journalIdentity checks a binding of the journal's cluster: it lives in any
// namespace and its scope is exactly that namespace (ADR-329).
func journalIdentity(b value.Binding, cluster string) bool {
	return value.BindingInCluster(b, cluster)
}

// bindingName keys a binding by namespace and name.
func bindingName(r value.Resource) string { return r.Namespace + "/" + r.Name }
func NewBindingJournal(s value.Snapshot, now time.Time) (*BindingJournal, error) {
	if !authorization.UUID(s.ClusterID) || !identity.Text(s.ControlNamespace.Name, 63) || !identity.Text(s.ControlNamespace.UID, 64) || !identity.Text(s.BindingResourceVersion, 128) || !identity.Fresh(s.ObservedAt, s.FreshUntil, now, 5*time.Second) {
		return nil, value.ErrInvalid
	}
	j := &BindingJournal{cluster: s.ClusterID, cursor: s.BindingResourceVersion, observed: s.ObservedAt, until: s.FreshUntil, byUID: map[string]value.Binding{}, names: map[string]string{}}
	for _, b := range s.Bindings {
		if !journalIdentity(b, j.cluster) || j.names[bindingName(b.Resource)] != "" {
			return nil, value.ErrInvalid
		}
		if _, exists := j.byUID[b.Resource.UID]; exists {
			return nil, value.ErrInvalid
		}
		j.byUID[b.Resource.UID] = cloneBinding(b)
		j.names[bindingName(b.Resource)] = b.Resource.UID
	}
	return j, nil
}

func (j *BindingJournal) Cursor() string { return j.cursor }

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
	if e.Binding == nil || !journalIdentity(*e.Binding, j.cluster) || e.Binding.Resource.ResourceVersion != e.ResourceVersion {
		return fail()
	}
	b := *e.Binding
	old, exists := j.byUID[b.Resource.UID]
	switch e.Type {
	case "ADDED":
		if exists || j.names[bindingName(b.Resource)] != "" {
			return fail()
		}
		j.byUID[b.Resource.UID] = cloneBinding(b)
		j.names[bindingName(b.Resource)] = b.Resource.UID
	case "MODIFIED", "DELETED":
		if !exists || bindingName(old.Resource) != bindingName(b.Resource) || old.Resource.NamespaceUID != b.Resource.NamespaceUID || b.Resource.Generation < old.Resource.Generation || b.Resource.Generation > old.Resource.Generation+1 || (b.Resource.Generation == old.Resource.Generation && b.Resource.SpecDigest != old.Resource.SpecDigest) || (old.Resource.Deleting && !b.Resource.Deleting && e.Type != "DELETED") {
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
			delete(j.names, bindingName(b.Resource))
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

func cloneBatch(b value.PermissionBatch) value.PermissionBatch {
	b.UnavailableClusters = slices.Clone(b.UnavailableClusters)
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
	input, err := permissionInputDigest(struct {
		Bindings  []value.Binding
		Inherited Inheritance `json:",omitzero"`
	}{bindings, inherited.withoutContinuity()})
	if err != nil {
		return value.PermissionBatch{}, value.ErrInvalid
	}
	batch := value.PermissionBatch{RootID: f.RootID, Epoch: f.Epoch, RequestID: request, ExpectedSequence: f.Sequence, TrustDigest: f.TrustDigest, InputDigest: input, ObservedAt: now, FreshUntil: j.until}
	for _, b := range bindings {
		if p, ok := bindingBasis(b, now); ok {
			p.Continuous = j.sequence > 0
			batch.Bases = append(batch.Bases, p)
		}
	}
	batch.Bases = append(batch.Bases, inherited.Bases...)
	batch.Bases = withIssuer(batch.Bases, j.Issuer)
	batch.UnavailableClusters = slices.Clone(inherited.UnavailableClusters)
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

// bindingBasis is the accepted basis of an active binding.
func bindingBasis(b value.Binding, now time.Time) (value.PermissionBasis, bool) {
	if b.Invalid || (b.Resource.Deleting && b.Effect == "Allow") || (!b.NotAfter.IsZero() && !now.Before(b.NotAfter)) {
		return value.PermissionBasis{}, false
	}
	p := value.PermissionBasis{Resource: b.Resource, Scope: b.Scope, Effect: b.Effect, Subjects: slices.Clone(b.Subjects), Roles: slices.Clone(b.Roles), NotAfter: b.NotAfter, Automation: b.Automation}
	p.Scope.Workloads = slices.Clone(b.Scope.Workloads)
	p.ScopeDigest = PermissionScopeDigest(p)
	return p, true
}

// withIssuer fills an omitted subject issuer with the installation's issuer
// (ADR-335 D4). Without a configured issuer such subjects grant and deny
// nothing; a basis left without subjects is dropped.
func withIssuer(bases []value.PermissionBasis, issuer string) []value.PermissionBasis {
	out := bases[:0]
	for _, p := range bases {
		var subjects []value.Subject
		for _, s := range p.Subjects {
			if s.Issuer == "" {
				s.Issuer = issuer
			}
			if s.Issuer != "" && !slices.Contains(subjects, s) {
				subjects = append(subjects, s)
			}
		}
		if len(subjects) == 0 {
			continue
		}
		p.Subjects = subjects
		out = append(out, p)
	}
	return out
}
