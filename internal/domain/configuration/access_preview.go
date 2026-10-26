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
// knobs: REQ-PER-002 bounds a preview to 1,000 target objects, and one reply
// must fit the shared operation output limit.
const (
	MaxPreviewChanges = 16
	MaxPreviewTargets = 1000
	MaxPreviewDeltas  = 64
	// OtherWorkloads is the preview cell that stands for every workload of a
	// namespace that no current or proposed binding names explicitly. A
	// namespace-wide assignment matches it; a workload-narrowed one does not.
	OtherWorkloads = "*"
	// ClusterUnavailable marks a cell outside the installation's enrolled
	// clusters; such a cell is never evaluated.
	ClusterUnavailable = "ClusterUnavailable"
)

// AccessChange is one proposed configuration change. Create and update carry
// the decoded AccessBinding spec; update and delete name the existing object's
// UID. PermissionSource changes are previewed only as deletion: a created or
// edited source derives subjects from live namespace metadata and qualified
// protection, which the preview does not observe.
type AccessChange struct {
	Action  string // "create", "update" or "delete"
	Kind    string // "AccessBinding" or "PermissionSource" (delete only)
	UID     string
	Binding Binding
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

// PreviewSnapshot is one consistent read of the accepted projection.
// Unmatched lists updated/deleted objects that hold no current assignment.
type PreviewSnapshot struct {
	Cells     []PreviewCell
	Unmatched []PreviewBasis
}

type AccessDelta struct {
	Target        authorization.Target
	Subject       Subject
	Operation     authorization.Operation
	Before, After authorization.Decision
	AfterUnmet    string
}

// AccessPreview is a query result, never a permit or an accepted projection.
type AccessPreview struct {
	Targets     int
	Unavailable []PreviewCell
	Deltas      []AccessDelta
	DeltasTotal int
	Unmatched   []PreviewBasis
}

func (p AccessPreview) Complete() bool { return len(p.Unavailable) == 0 }

func validChangeBinding(b Binding) bool {
	return (b.Effect == "Allow" || b.Effect == "Deny") && len(b.Subjects) > 0 && len(b.Subjects) <= 32 && len(b.Roles) > 0 && len(b.Roles) <= 4 &&
		authorization.UUID(b.Scope.ClusterID) && identity.Text(b.Scope.Namespace.UID, 64) && len(b.Scope.Workloads) <= 64 && b.Resource.SpecDigest != (artifact.Digest{})
}

// PreviewChanges validates the proposal, names each proposed binding's object
// and returns the projection read it needs.
func PreviewChanges(changes []AccessChange) ([]AccessChange, PreviewRead, error) {
	if len(changes) < 1 || len(changes) > MaxPreviewChanges {
		return nil, PreviewRead{}, ErrLimit
	}
	out := slices.Clone(changes)
	read := PreviewRead{Workloads: map[PreviewNamespace][]string{}}
	seen := map[PreviewBasis]bool{}
	for n := range out {
		c := &out[n]
		switch {
		case c.Action == "create" && c.Kind == "AccessBinding" && c.UID == "":
			c.Binding.Resource.UID = "proposed-" + strconv.Itoa(n+1)
		case c.Action == "update" && c.Kind == "AccessBinding" && identity.Text(c.UID, 64):
			c.Binding.Resource.UID = c.UID
		case c.Action == "delete" && (c.Kind == "AccessBinding" || c.Kind == "PermissionSource") && identity.Text(c.UID, 64):
		default:
			return nil, PreviewRead{}, ErrInvalid
		}
		ref := PreviewBasis{c.Kind, c.UID}
		if c.UID != "" {
			if seen[ref] {
				return nil, PreviewRead{}, ErrInvalid
			}
			seen[ref] = true
			read.Bases = append(read.Bases, ref)
		}
		if c.Action == "delete" {
			continue
		}
		c.Binding.Resource.Kind = "AccessBinding"
		if !validChangeBinding(c.Binding) {
			return nil, PreviewRead{}, ErrInvalid
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
// current projection are reported Indeterminate and never evaluated.
func PreviewAccess(changes []AccessChange, snap PreviewSnapshot, administered []string, policy identity.Revision, now time.Time) (AccessPreview, error) {
	if len(snap.Cells) > MaxPreviewTargets {
		return AccessPreview{}, ErrLimit
	}
	out := AccessPreview{Targets: len(snap.Cells), Unmatched: snap.Unmatched}
	for _, cell := range snap.Cells {
		if !slices.Contains(administered, cell.Target.ClusterID) {
			cell.Unavailable = ClusterUnavailable
		}
		if cell.Unavailable != "" {
			cell.Projection = authorization.Projection{}
			out.Unavailable = append(out.Unavailable, cell)
			continue
		}
		after, subjects := applyChanges(cell, changes, now)
		for _, s := range subjects {
			i := previewIdentity(s, cell.Projection, after, policy, now)
			for _, op := range previewOperations {
				before, _ := authorization.Decide(i, cell.Projection, op, cell.Target, now)
				decision, unmet := authorization.Decide(i, after, op, cell.Target, now)
				if before == decision {
					continue
				}
				out.DeltasTotal++
				if len(out.Deltas) < MaxPreviewDeltas {
					out.Deltas = append(out.Deltas, AccessDelta{cell.Target, s, op, before, decision, unmet})
				}
			}
		}
	}
	return out, nil
}

// applyChanges removes the assignments of updated/deleted objects and adds the
// candidates the observation's own ProposeBinding derives for the cell. Added
// rows carry placeholder assignment IDs and the proposal's spec digest; they
// exist only for this evaluation.
func applyChanges(cell PreviewCell, changes []AccessChange, now time.Time) (authorization.Projection, []Subject) {
	p := cell.Projection
	after := p
	after.Allows, after.Denies = nil, nil
	var subjects []Subject
	touch := func(a artifact.AudienceAssignment) {
		s := Subject{a.Kind, a.Issuer, a.SubjectID}
		if !slices.Contains(subjects, s) {
			subjects = append(subjects, s)
		}
	}
	removed := func(a artifact.AudienceAssignment) bool {
		return slices.ContainsFunc(changes, func(c AccessChange) bool {
			return c.UID != "" && c.Kind == a.BasisKind && c.UID == a.BasisUID
		})
	}
	keep := func(rows []authorization.CurrentAssignment) []authorization.CurrentAssignment {
		var kept []authorization.CurrentAssignment
		for _, r := range rows {
			if removed(r.Audience) {
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
	return after, subjects
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
