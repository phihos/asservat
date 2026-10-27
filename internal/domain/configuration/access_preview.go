package configuration

import (
	"cmp"
	"slices"
	"strconv"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-237 permission impact preview bounds. They are constants, not tuning
// knobs: REQ-PER-002 bounds a preview to 1,000 target objects and a 256 KiB
// result. MaxPreviewDeltas only bounds memory; the listed result is bounded
// by its serialized size in the presentation layer.
const (
	MaxPreviewChanges = 16
	MaxPreviewTargets = 1000
	MaxPreviewDeltas  = 4096
	// OtherWorkloads is the preview cell that stands for every workload of a
	// namespace that no current or proposed binding names explicitly. A
	// namespace-wide assignment matches it; a workload-narrowed one does not.
	OtherWorkloads = "*"
	// ClusterUnavailable marks a cell outside the installation's enrolled
	// clusters; such a cell is never evaluated.
	ClusterUnavailable = "ClusterUnavailable"
)

// AccessChange is one proposed configuration change. AccessBinding create and
// update carry the decoded spec; update and delete name the existing object's
// UID. A PermissionSource create/update carries its decoded spec and is
// evaluated through the namespace grants that the accepted namespace
// observation yields for it (ADR-242); its delete removes the source's
// current assignments.
type AccessChange struct {
	Action  string // "create", "update" or "delete"
	Kind    string // "AccessBinding" or "PermissionSource"
	UID     string
	Binding Binding
	Source  Source
	// Grants and Unevaluated are a source change's derivation from the
	// snapshot. Unevaluated (MetadataUnavailable, MetadataNotObserved or
	// DecisionTimeSource)
	// makes the change Indeterminate: it is listed in NotEvaluated and an
	// updated source's current assignments stay in the after state.
	Grants      []NamespaceGrant
	Unevaluated string
}

func (c AccessChange) sourceSpec() bool { return c.Kind == "PermissionSource" && c.Action != "delete" }

// evaluated reports whether the change's effect is known: everything but a
// source change whose namespace metadata is unknown.
func (c AccessChange) evaluated() bool { return !c.sourceSpec() || c.Unevaluated == "" }

// PreviewSourceGrants is what the accepted namespace observation yields for
// one proposed source: its namespace grants, or Unevaluated when the
// observation is unavailable or lacks the source's keys.
type PreviewSourceGrants struct {
	Grants      []NamespaceGrant
	Unevaluated string
}

type PreviewBasis struct{ Kind, UID string }
type PreviewNamespace struct{ ClusterID, NamespaceUID string }

// PreviewRead asks the accepted projection store for the cells of every
// namespace that a proposed binding names or that holds an updated/deleted
// object, plus the workload UIDs the proposals name explicitly.
type PreviewRead struct {
	Namespaces []PreviewNamespace
	Workloads  map[PreviewNamespace][]string
	Bases      []PreviewBasis
	// Sources are the proposed PermissionSource specs (creates and updates)
	// in change order; the snapshot returns their grants from the accepted
	// namespace observation and reads the cells of the namespaces granted.
	Sources []Source
	// Allowed, when set, restricts which namespaces may match an updated or
	// deleted object: a delegated previewer's envelope namespaces. A match
	// elsewhere is reported Unmatched, exactly like a nonexistent object.
	Allowed []PreviewNamespace
}

// PreviewCell is one workload scope with its current accepted projection.
// Assignments are scoped to workloads, so Target.PodUID repeats the workload
// UID; the evaluator only compares it with the projection's own target.
// Unavailable names why the projection could not be read; the cell is then
// Indeterminate, never evaluated.
type PreviewCell struct {
	Target      authorization.Target
	Projection  authorization.Projection
	Unavailable string
	// Unknown are decision-time assignments (ADR-245) recorded for this
	// workload whose current SubjectAccessReview outcome is not known (no
	// current allowed decision). Removing one is Indeterminate before.
	Unknown []artifact.AudienceAssignment `json:",omitempty"`
}

func (c PreviewCell) Other() bool { return c.Target.WorkloadUID == OtherWorkloads }

// PreviewSnapshot is one consistent read of the accepted projection at
// Revision (the permission stream). Unmatched lists updated/deleted objects
// that hold no current assignment.
type PreviewSnapshot struct {
	Revision  identity.Revision
	Cells     []PreviewCell
	Unmatched []PreviewBasis
	// Sources answers PreviewRead.Sources, in the same order.
	Sources []PreviewSourceGrants
}

// PreviewAssignment is one assignment that decided a preview decision: a
// contributing allow or the matching deny. Proposed marks a row derived from
// the proposal (its revision is the proposed spec digest).
type PreviewAssignment struct {
	Effect     string
	Assignment artifact.AudienceAssignment
	Proposed   bool
}

type AccessDelta struct {
	Target                  authorization.Target
	Subject                 Subject
	Operation               authorization.Operation
	Before, After           authorization.Decision
	BeforeUnmet, AfterUnmet string
	BeforeBasis, AfterBasis []PreviewAssignment
	AfterValidUntil         time.Time
}

// AccessPreview is a query result, never a permit or an accepted projection.
// FreshUntil is the earliest freshness expiry of the evaluated projections.
type AccessPreview struct {
	Revision     identity.Revision
	Targets      int
	Unavailable  []PreviewCell
	Deltas       []AccessDelta
	DeltasTotal  int
	Unmatched    []PreviewBasis
	NotEvaluated []AccessChange
	FreshUntil   time.Time
}

func (p AccessPreview) Complete() bool { return len(p.Unavailable) == 0 && len(p.NotEvaluated) == 0 }

// PreviewEnvelope is a delegated permission writer's trusted delegation
// envelope (ADR-189) as granted to a browser previewer: exact cluster and
// namespace, optional workloads, allowed roles and subject issuers. A nil
// envelope list means installation-wide administration.
type PreviewEnvelope struct {
	Scope          Scope
	Roles, Issuers []string
}

func (e PreviewEnvelope) covers(t authorization.Target) bool {
	if t.ClusterID != e.Scope.ClusterID || t.NamespaceUID != e.Scope.Namespace.UID {
		return false
	}
	return len(e.Scope.Workloads) == 0 || slices.ContainsFunc(e.Scope.Workloads, func(w WorkloadRef) bool { return w.UID == t.WorkloadUID })
}

// admits mirrors the delegation part of the native permission guard for a
// proposed object: exact cluster and namespace, workloads within the
// envelope, allowed roles and issuers, and no automation envelope.
func (e PreviewEnvelope) admits(b Binding) bool {
	if b.Scope.ClusterID != e.Scope.ClusterID || b.Scope.Namespace != e.Scope.Namespace || b.Automation != nil {
		return false
	}
	if len(e.Scope.Workloads) != 0 {
		if len(b.Scope.Workloads) == 0 {
			return false
		}
		for _, w := range b.Scope.Workloads {
			if !slices.Contains(e.Scope.Workloads, w) {
				return false
			}
		}
	}
	for _, r := range b.Roles {
		if !slices.Contains(e.Roles, r) {
			return false
		}
	}
	for _, s := range b.Subjects {
		if !slices.Contains(e.Issuers, s.Issuer) {
			return false
		}
	}
	return true
}

func (e PreviewEnvelope) admitsRow(t authorization.Target, a artifact.AudienceAssignment) bool {
	return e.covers(t) && slices.Contains(e.Roles, a.Role) && slices.Contains(e.Issuers, a.Issuer)
}

func validChangeBinding(b Binding) bool {
	return (b.Effect == "Allow" || b.Effect == "Deny") && len(b.Subjects) > 0 && len(b.Subjects) <= 32 && len(b.Roles) > 0 && len(b.Roles) <= 4 &&
		authorization.UUID(b.Scope.ClusterID) && identity.Text(b.Scope.Namespace.UID, 64) && len(b.Scope.Workloads) <= 64 && b.Resource.SpecDigest != (artifact.Digest{})
}

// PreviewChanges validates the proposal against the caller's authority, names
// each proposed binding's object and returns the projection read it needs.
// With envelopes (a delegated writer), every proposed object must fit one
// envelope and PermissionSource changes are refused, as the native guard
// refuses them (ErrDenied).
func PreviewChanges(changes []AccessChange, envelopes []PreviewEnvelope) ([]AccessChange, PreviewRead, error) {
	if len(changes) < 1 || len(changes) > MaxPreviewChanges {
		return nil, PreviewRead{}, ErrLimit
	}
	out := slices.Clone(changes)
	read := PreviewRead{Workloads: map[PreviewNamespace][]string{}}
	seen := map[PreviewBasis]bool{}
	for n := range out {
		c := &out[n]
		switch {
		case c.Action == "create" && c.UID == "" && (c.Kind == "AccessBinding" || c.Kind == "PermissionSource"):
			c.Binding.Resource.UID = "proposed-" + strconv.Itoa(n+1)
			c.Source.Resource.UID = c.Binding.Resource.UID
		case c.Action == "update" && (c.Kind == "AccessBinding" || c.Kind == "PermissionSource") && identity.Text(c.UID, 64):
			c.Binding.Resource.UID = c.UID
			c.Source.Resource.UID = c.UID
		case c.Action == "delete" && (c.Kind == "AccessBinding" || c.Kind == "PermissionSource") && identity.Text(c.UID, 64):
		default:
			return nil, PreviewRead{}, ErrInvalid
		}
		if c.Kind == "PermissionSource" && envelopes != nil {
			return nil, PreviewRead{}, ErrDenied
		}
		ref := PreviewBasis{c.Kind, c.UID}
		if c.UID != "" {
			if seen[ref] {
				return nil, PreviewRead{}, ErrInvalid
			}
			seen[ref] = true
			read.Bases = append(read.Bases, ref)
		}
		if c.sourceSpec() {
			if !authorization.UUID(c.Source.ClusterID) || c.Source.Resource.SpecDigest == (artifact.Digest{}) {
				return nil, PreviewRead{}, ErrInvalid
			}
			c.Source.Resource.Kind = "PermissionSource"
			c.Grants, c.Unevaluated = nil, ""
			read.Sources = append(read.Sources, c.Source)
			continue
		}
		if c.Action == "delete" {
			continue
		}
		c.Binding.Resource.Kind = "AccessBinding"
		if !validChangeBinding(c.Binding) {
			return nil, PreviewRead{}, ErrInvalid
		}
		if envelopes != nil && !slices.ContainsFunc(envelopes, func(e PreviewEnvelope) bool { return e.admits(c.Binding) }) {
			return nil, PreviewRead{}, ErrDenied
		}
		ns := PreviewNamespace{c.Binding.Scope.ClusterID, c.Binding.Scope.Namespace.UID}
		if !slices.Contains(read.Namespaces, ns) {
			read.Namespaces = append(read.Namespaces, ns)
		}
		for _, w := range c.Binding.Scope.Workloads {
			if w.UID == OtherWorkloads {
				return nil, PreviewRead{}, ErrInvalid
			}
			if !slices.Contains(read.Workloads[ns], w.UID) {
				read.Workloads[ns] = append(read.Workloads[ns], w.UID)
			}
		}
	}
	// A delegated previewer always reads every envelope namespace, so the
	// target set does not depend on whether an updated or deleted UID exists.
	for _, e := range envelopes {
		ns := PreviewNamespace{e.Scope.ClusterID, e.Scope.Namespace.UID}
		if !slices.Contains(read.Allowed, ns) {
			read.Allowed = append(read.Allowed, ns)
		}
		if !slices.Contains(read.Namespaces, ns) {
			read.Namespaces = append(read.Namespaces, ns)
		}
	}
	return out, read, nil
}

var previewOperations = []authorization.Operation{authorization.CollectContext, authorization.ReadApproved, authorization.DownloadApproved}

// PreviewAccess applies the validated changes to every cell of the snapshot
// and compares the ordinary evaluator's decision before and after for each
// subject whose assignments the change adds or removes. Each subject is
// evaluated as a principal holding only that subject (a group subject as one
// member of that group with no other groups), with every client scope, so the
// result describes configuration rather than one client. Group members are
// never enumerated. Cells outside the administered clusters or without a
// current projection are reported Indeterminate and never evaluated. With
// envelopes, only cells inside them are reported, and an updated or deleted
// object with any current assignment outside them is neither removed nor
// evaluated: it is reported Unmatched, exactly like an object that does not
// exist, so a previewer cannot learn about objects beyond their envelope.
func PreviewAccess(changes []AccessChange, snap PreviewSnapshot, administered []string, envelopes []PreviewEnvelope, policy identity.Revision, now time.Time) (AccessPreview, error) {
	if len(snap.Cells) > MaxPreviewTargets {
		return AccessPreview{}, ErrLimit
	}
	out := AccessPreview{Revision: snap.Revision}
	// Attach each proposed source's grants from the accepted namespace
	// observation, in change order.
	changes = slices.Clone(changes)
	sources := 0
	for n := range changes {
		if !changes[n].sourceSpec() {
			continue
		}
		if sources == len(snap.Sources) {
			return AccessPreview{}, ErrInvalid
		}
		changes[n].Grants, changes[n].Unevaluated = snap.Sources[sources].Grants, snap.Sources[sources].Unevaluated
		sources++
		if !changes[n].evaluated() {
			out.NotEvaluated = append(out.NotEvaluated, changes[n])
		}
	}
	if sources != len(snap.Sources) {
		return AccessPreview{}, ErrInvalid
	}
	unmatched, requested := slices.Clone(snap.Unmatched), changes
	if envelopes != nil {
		// For a delegated previewer an updated or deleted object counts as
		// matched only when that is proven: every cell was read, at least
		// one of its current assignments is visible, and all of them lie
		// inside the envelope. Anything else (foreign, wider than the
		// envelope, hidden by an unavailable cell, no visible assignment) is
		// reported exactly like a nonexistent UID: Unmatched, nothing
		// removed, and an update still adds its proposed rows.
		available := !slices.ContainsFunc(snap.Cells, func(c PreviewCell) bool { return c.Unavailable != "" })
		var effective []AccessChange
		for _, c := range changes {
			if c.UID == "" || c.sourceSpec() {
				effective = append(effective, c)
				continue
			}
			seen, admitted := false, true
			for _, cell := range snap.Cells {
				for _, rows := range [][]authorization.CurrentAssignment{cell.Projection.Allows, cell.Projection.Denies} {
					for _, r := range rows {
						if removedBy([]AccessChange{c}, r.Audience) {
							seen = true
							admitted = admitted && slices.ContainsFunc(envelopes, func(e PreviewEnvelope) bool { return e.admitsRow(cell.Target, r.Audience) })
						}
					}
				}
			}
			if !available || !seen || !admitted {
				if ref := (PreviewBasis{c.Kind, c.UID}); !slices.Contains(unmatched, ref) {
					unmatched = append(unmatched, ref)
				}
				c.UID = ""
			}
			effective = append(effective, c)
		}
		changes = effective
	}
	// Report unmatched objects in request order, independent of why.
	for _, c := range requested {
		if ref := (PreviewBasis{c.Kind, c.UID}); c.UID != "" && slices.Contains(unmatched, ref) && !slices.Contains(out.Unmatched, ref) {
			out.Unmatched = append(out.Unmatched, ref)
		}
	}
	for _, cell := range snap.Cells {
		if envelopes != nil && !slices.ContainsFunc(envelopes, func(e PreviewEnvelope) bool { return e.covers(cell.Target) }) {
			continue
		}
		out.Targets++
		if !slices.Contains(administered, cell.Target.ClusterID) {
			cell.Unavailable = ClusterUnavailable
		}
		if cell.Unavailable != "" {
			cell.Projection = authorization.Projection{}
			out.Unavailable = append(out.Unavailable, cell)
			continue
		}
		p := cell.Projection
		for _, until := range []time.Time{p.FreshUntil, p.DeniesFreshUntil} {
			if out.FreshUntil.IsZero() || until.Before(out.FreshUntil) {
				out.FreshUntil = until
			}
		}
		after, subjects, proposed := applyChanges(cell, changes, now)
		basis := func(e authorization.Explanation) []PreviewAssignment {
			var rows []PreviewAssignment
			for _, a := range e.Assignments {
				rows = append(rows, PreviewAssignment{a.Effect, a.Assignment, proposed[a.Assignment.AssignmentID]})
			}
			return rows
		}
		// A removed decision-time assignment without a current decision: the
		// access it would confer is unknown before, and known after.
		for _, a := range cell.Unknown {
			s := Subject{a.Kind, a.Issuer, a.SubjectID}
			if !removedBy(changes, a) || slices.Contains(subjects, s) {
				continue
			}
			i := previewIdentity(s, cell.Projection, after, policy, now)
			assumed := cell.Projection
			assumed.Allows = append(slices.Clone(assumed.Allows), authorization.CurrentAssignment{Audience: a, ObservedAt: now, FreshUntil: assumed.FreshUntil, Reviewed: true})
			for _, op := range previewOperations {
				if authorization.Decide(i, assumed, op, cell.Target, now).Decision != authorization.Allow {
					continue
				}
				decided := authorization.Decide(i, after, op, cell.Target, now)
				if decided.Decision == authorization.Allow {
					continue
				}
				out.DeltasTotal++
				if len(out.Deltas) < MaxPreviewDeltas {
					out.Deltas = append(out.Deltas, AccessDelta{Target: cell.Target, Subject: s, Operation: op, Before: authorization.Indeterminate, After: decided.Decision,
						BeforeUnmet: DecisionTimeSource, BeforeBasis: []PreviewAssignment{{Effect: "Allow", Assignment: a}}, AfterUnmet: decided.Unmet, AfterBasis: basis(decided), AfterValidUntil: decided.ValidUntil})
				}
			}
		}
		for _, s := range subjects {
			i := previewIdentity(s, cell.Projection, after, policy, now)
			for _, op := range previewOperations {
				before := authorization.Decide(i, cell.Projection, op, cell.Target, now)
				decided := authorization.Decide(i, after, op, cell.Target, now)
				if before.Decision == decided.Decision {
					continue
				}
				out.DeltasTotal++
				if len(out.Deltas) < MaxPreviewDeltas {
					out.Deltas = append(out.Deltas, AccessDelta{Target: cell.Target, Subject: s, Operation: op, Before: before.Decision, After: decided.Decision,
						BeforeUnmet: before.Unmet, AfterUnmet: decided.Unmet, BeforeBasis: basis(before), AfterBasis: basis(decided), AfterValidUntil: decided.ValidUntil})
				}
			}
		}
	}
	return out, nil
}

func removedBy(changes []AccessChange, a artifact.AudienceAssignment) bool {
	return slices.ContainsFunc(changes, func(c AccessChange) bool {
		return c.UID != "" && c.evaluated() && c.Kind == a.BasisKind && c.UID == a.BasisUID
	})
}

// applyChanges removes the assignments of updated/deleted objects and adds the
// candidates the observation's own ProposeBinding derives for the cell. Added
// rows carry placeholder assignment IDs (returned as proposed) and the
// proposal's spec digest; they exist only for this evaluation.
func applyChanges(cell PreviewCell, changes []AccessChange, now time.Time) (authorization.Projection, []Subject, map[string]bool) {
	p := cell.Projection
	after := p
	var subjects []Subject
	proposed := map[string]bool{}
	touch := func(a artifact.AudienceAssignment) {
		s := Subject{a.Kind, a.Issuer, a.SubjectID}
		if !slices.Contains(subjects, s) {
			subjects = append(subjects, s)
		}
	}
	keep := func(rows []authorization.CurrentAssignment) []authorization.CurrentAssignment {
		var kept []authorization.CurrentAssignment
		for _, r := range rows {
			if removedBy(changes, r.Audience) {
				touch(r.Audience)
				continue
			}
			kept = append(kept, r)
		}
		return kept
	}
	after.Allows, after.Denies = keep(p.Allows), keep(p.Denies)
	added := 0
	for _, c := range changes {
		if c.sourceSpec() {
			// A namespace grant covers every workload of its namespace.
			for _, g := range c.Grants {
				if !c.evaluated() || c.Source.ClusterID != cell.Target.ClusterID || g.Namespace.UID != cell.Target.NamespaceUID {
					continue
				}
				for _, subject := range g.Subjects {
					added++
					a := artifact.AudienceAssignment{Kind: subject.Kind, Issuer: subject.Issuer, SubjectID: subject.ID, Role: c.Source.Role,
						BasisKind: "PermissionSource", BasisUID: c.Source.Resource.UID, AssignmentID: placeholderAssignment(added), BasisDigest: c.Source.Resource.SpecDigest}
					proposed[a.AssignmentID] = true
					after.Allows = append(after.Allows, authorization.CurrentAssignment{Audience: a, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil})
					touch(a)
				}
			}
			continue
		}
		if c.Action == "delete" {
			continue
		}
		b := c.Binding
		target := Target{ClusterID: cell.Target.ClusterID, Namespace: NamespaceRef{UID: cell.Target.NamespaceUID}, Workload: WorkloadRef{UID: cell.Target.WorkloadUID}}
		if b.Scope.Namespace.UID == target.Namespace.UID {
			target.Namespace = b.Scope.Namespace
		}
		if i := slices.IndexFunc(b.Scope.Workloads, func(w WorkloadRef) bool { return w.UID == target.Workload.UID }); i >= 0 {
			target.Workload = b.Scope.Workloads[i]
		}
		proposal := ProposeBinding(b, target, now)
		if proposal.Reason != "RequiresAcceptance" {
			continue
		}
		until := p.FreshUntil
		if !b.NotAfter.IsZero() {
			until = identity.Earlier(until, b.NotAfter)
		}
		for _, candidate := range proposal.Candidates {
			added++
			a := artifact.AudienceAssignment{Kind: candidate.Subject.Kind, Issuer: candidate.Subject.Issuer, SubjectID: candidate.Subject.ID, Role: candidate.Role,
				BasisKind: "AccessBinding", BasisUID: b.Resource.UID, AssignmentID: placeholderAssignment(added), BasisDigest: b.Resource.SpecDigest}
			proposed[a.AssignmentID] = true
			row := authorization.CurrentAssignment{Audience: a, ObservedAt: p.ObservedAt, FreshUntil: until}
			if candidate.Effect == "Deny" {
				after.Denies = append(after.Denies, row)
			} else {
				after.Allows = append(after.Allows, row)
			}
			touch(a)
		}
	}
	slices.SortFunc(subjects, func(a, b Subject) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Issuer, b.Issuer), cmp.Compare(a.ID, b.ID))
	})
	return after, subjects, proposed
}

func placeholderAssignment(n int) string {
	hex := strconv.FormatInt(int64(n), 16)
	for len(hex) < 12 {
		hex = "0" + hex
	}
	return "00000000-0000-4000-8000-" + hex
}

// previewIdentity is the synthetic principal for one subject. A group subject
// needs a principal subject that matches no User/Workload row of either
// projection, so only the group's own rows apply to it.
func previewIdentity(s Subject, before, after authorization.Projection, policy identity.Revision, now time.Time) identity.Identity {
	i := identity.Identity{Principal: identity.Principal{Issuer: s.Issuer, Subject: s.ID, ClientID: "asservat-access-preview", Kind: identity.Human},
		Scopes: []string{"evidence:capture", "evidence:read", "evidence:download"}, Policy: policy, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
	switch s.Kind {
	case "Workload":
		i.Principal.Kind = identity.Workload
	case "Group":
		i.Groups = []string{s.ID}
		used := func(id string) bool {
			for _, rows := range [][]authorization.CurrentAssignment{before.Allows, before.Denies, after.Allows, after.Denies} {
				if slices.ContainsFunc(rows, func(r authorization.CurrentAssignment) bool {
					return r.Audience.Kind != "Group" && r.Audience.Issuer == s.Issuer && r.Audience.SubjectID == id
				}) {
					return true
				}
			}
			return false
		}
		i.Principal.Subject = "asservat-preview-group-member"
		for n := 1; used(i.Principal.Subject); n++ {
			i.Principal.Subject = "asservat-preview-group-member-" + strconv.Itoa(n)
		}
	}
	return i
}
