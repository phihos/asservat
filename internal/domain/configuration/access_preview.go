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
	// InheritanceNotAccepted marks a PermissionSource create/update: the
	// installation accepts explicit bindings only (permission-acceptance.md),
	// so a source changes no current assignment and its derived subjects are
	// unknown. Its effect is Indeterminate, never Allow.
	InheritanceNotAccepted = "InheritanceNotAccepted"
)

// AccessChange is one proposed configuration change. AccessBinding create and
// update carry the decoded spec; update and delete name the existing object's
// UID. A PermissionSource create/update carries its decoded spec and is
// reported Indeterminate (InheritanceNotAccepted); its delete removes the
// source's current assignments.
type AccessChange struct {
	Action  string // "create", "update" or "delete"
	Kind    string // "AccessBinding" or "PermissionSource"
	UID     string
	Binding Binding
	Source  Source
}

func (c AccessChange) sourceSpec() bool { return c.Kind == "PermissionSource" && c.Action != "delete" }

type PreviewBasis struct{ Kind, UID string }
type PreviewNamespace struct{ ClusterID, NamespaceUID string }

// PreviewRead asks the accepted projection store for the cells of every
// namespace that a proposed binding names or that holds an updated/deleted
// object, plus the workload UIDs the proposals name explicitly.
type PreviewRead struct {
	Namespaces []PreviewNamespace
	Workloads  map[PreviewNamespace][]string
	Bases      []PreviewBasis
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
}

func (c PreviewCell) Other() bool { return c.Target.WorkloadUID == OtherWorkloads }

// PreviewSnapshot is one consistent read of the accepted projection at
// Revision (the permission stream). Unmatched lists updated/deleted objects
// that hold no current assignment.
type PreviewSnapshot struct {
	Revision  identity.Revision
	Cells     []PreviewCell
	Unmatched []PreviewBasis
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
		case c.Action == "update" && (c.Kind == "AccessBinding" || c.Kind == "PermissionSource") && identity.Text(c.UID, 64):
			c.Binding.Resource.UID = c.UID
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
			if !c.sourceSpec() {
				read.Bases = append(read.Bases, ref)
			}
		}
		if c.sourceSpec() {
			if !authorization.UUID(c.Source.ClusterID) || c.Source.Resource.SpecDigest == (artifact.Digest{}) {
				return nil, PreviewRead{}, ErrInvalid
			}
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
// envelopes, an updated or deleted object must lie within the caller's
// envelopes (ErrDenied otherwise, as the native guard checks the existing
// object) and only cells inside them are reported.
func PreviewAccess(changes []AccessChange, snap PreviewSnapshot, administered []string, envelopes []PreviewEnvelope, policy identity.Revision, now time.Time) (AccessPreview, error) {
	if len(snap.Cells) > MaxPreviewTargets {
		return AccessPreview{}, ErrLimit
	}
	out := AccessPreview{Revision: snap.Revision, Unmatched: snap.Unmatched}
	for _, c := range changes {
		if c.sourceSpec() {
			out.NotEvaluated = append(out.NotEvaluated, c)
		}
	}
	if envelopes != nil {
		for _, cell := range snap.Cells {
			for _, rows := range [][]authorization.CurrentAssignment{cell.Projection.Allows, cell.Projection.Denies} {
				for _, r := range rows {
					if removedBy(changes, r.Audience) && !slices.ContainsFunc(envelopes, func(e PreviewEnvelope) bool { return e.admitsRow(cell.Target, r.Audience) }) {
						return AccessPreview{}, ErrDenied
					}
				}
			}
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
		return c.UID != "" && !c.sourceSpec() && c.Kind == a.BasisKind && c.UID == a.BasisUID
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
		if c.Action == "delete" || c.sourceSpec() {
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
