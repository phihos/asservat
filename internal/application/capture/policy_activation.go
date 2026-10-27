package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// PolicyDocuments reads hub-held DebugPolicies (ADR-228) by name; uid pins
// the object ("" for activation). Status is never authority.
type PolicyDocuments interface {
	ReadPolicy(ctx context.Context, name, uid string) (value.PolicySource, []byte, error)
}

// RestartObserver is the delegated regional restart observation.
type RestartObserver interface {
	ObserveWorkloadRestarts(context.Context, targets.RestartRequest) (targets.RestartObservation, error)
}

// PolicyPermissions is the current accepted permission projection.
type PolicyPermissions interface {
	Permissions(context.Context, authorization.Target) (authorization.Projection, error)
}

// PolicyActivationLedger holds the activation's read-only SQL facts.
type PolicyActivationLedger interface {
	Delegation(context.Context, authorization.Target) (identity.Revision, error)
	ActiveClusterPolicies(ctx context.Context, cluster, except string) (int64, error)
	AcceptanceByNonce(context.Context, string) (value.PolicyAcceptance, bool, error)
	Status(context.Context, string) (value.PolicyStatus, error)
}

// PolicyAuditPublisher writes and acknowledges pending encrypted acceptance
// audit records; acceptance is not eligible before acknowledgement.
type PolicyAuditPublisher interface {
	PublishPolicyAcceptances(context.Context) error
}

// PolicyActivation is the authenticated human's activation of one hub-held
// DebugPolicy (ADR-228). The human submits in-process over an authenticated
// MCP/browser request, so the submission check is built here; a separate
// GitOps or admission submitter would need the ADR-062 signed path instead.
// The current submitter must hold whole-pod collection rights and belong to
// a sponsoring group of the sole automation-bearing AccessBinding.
type PolicyActivation struct {
	RootID, InstallationID string
	RecipeName             string
	RecipeDigest           artifact.Digest
	Documents              PolicyDocuments
	Sources                PolicySourceWriter
	Observer               RestartObserver
	Ledger                 PolicyActivationLedger
	Permissions            PolicyPermissions
	Automation             authapp.AutomationAuthorityReader
	// Recorder activation reads real workload delegation directly; it never
	// creates a placeholder Pod or draft authority to select an envelope.
	WorkloadAutomation authapp.WorkloadAutomationAuthorityReader
	CompileRecorder    PolicyRecorderCompiler
	Acceptor           PolicyAcceptor
	Audit              PolicyAuditPublisher
	Recovery           fleetapp.RecoveryReader
	Now                func() time.Time
	// Report receives a fixed refusal stage; diagnostics only.
	Report func(string)
}

// PolicyActivationResult is response metadata, never a permit.
type PolicyActivationResult struct {
	PolicyUID, AcceptanceID string
	NotAfter                time.Time
	MaxExecutions           int64
	Replay, Audited         bool
	// Sharing is the accepted recurring sharing (ADR-239), if any.
	Sharing *value.PolicyShareInstruction
}

// refused reports the failed step and the error's fixed class; never text.
func (s PolicyActivation) refused(stage string, err error) error {
	if s.Report != nil {
		s.Report(stage + "/" + failureClass(err))
	}
	return err
}

func (s PolicyActivation) delegationRefused(stage string) error {
	if s.Report != nil {
		s.Report("delegation/" + stage)
	}
	return ErrPolicyDelegation
}

// ErrPolicyDeactivated means this exact revision and delegation was
// deactivated; only a changed DebugPolicy (or delegation) can be activated.
var ErrPolicyDeactivated = errors.New("policy revision deactivated")

// ErrPolicyDelegation means no sole automation-bearing AccessBinding, or the
// submitter is in none of its sponsoring groups (DelegationRequired).
var ErrPolicyDelegation = errors.New("policy delegation required")

func (s PolicyActivation) configured() bool {
	return authorization.UUID(s.RootID) && authorization.UUID(s.InstallationID) && s.RecipeName != "" && s.RecipeDigest != (artifact.Digest{}) && s.Documents != nil && s.Sources != nil && s.Observer != nil && s.Ledger != nil && s.Permissions != nil && s.Automation != nil && s.Acceptor != nil && s.Audit != nil && s.Recovery != nil && s.Now != nil
}

// policyNonce derives the submission nonce from the authenticated actor, the
// policy object and the caller's idempotency key: a retried activation finds
// its original receipt instead of creating a second acceptance.
func policyNonce(actor identity.Principal, policy, key string) string {
	b, _ := json.Marshal(struct {
		Format, Policy, Key string
		Actor               identity.Principal
	}{"policy-activation-nonce/v1", policy, key, actor})
	h := sha256.Sum256(b)
	h[6] = h[6]&0x0f | 0x40
	h[8] = h[8]&0x3f | 0x80
	x := hex.EncodeToString(h[:16])
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

// ErrSharingReviewRequired refuses the first activation of a policy that
// shares its captures (ADR-239, REQ-SHR-005): the caller must review that
// repeated collections will be shared and with whom, then activate again with
// sharingReviewed. PolicySharingReview carries the reviewed scope.
var ErrSharingReviewRequired = errors.New("policy sharing review required")

// PolicySharingReview is the review statement of a policy's recurring
// sharing, returned before acceptance: who receives the repeated collections,
// how many captures at most and until when.
type PolicySharingReview struct{ Instruction value.PolicyShareInstruction }

func (r PolicySharingReview) Error() string { return ErrSharingReviewRequired.Error() }
func (r PolicySharingReview) Unwrap() error { return ErrSharingReviewRequired }

// Activate accepts the current revision of one policy. A retry under the same
// key returns the original acceptance; a changed policy needs a new key. A
// policy with spec.sharing is accepted only with sharingReviewed; otherwise
// every check runs and the review statement is returned instead.
func (s PolicyActivation) Activate(ctx context.Context, current identities.CurrentIdentity, name, key string, sharingReviewed bool) (PolicyActivationResult, error) {
	var zero PolicyActivationResult
	if !s.configured() || ctx == nil || current == nil || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	if !identity.Text(name, 253) || !identity.Text(key, 128) {
		return zero, value.ErrInvalid
	}
	author, err := current.ResolveIdentity(ctx)
	if err != nil || !author.Valid(s.Now()) || author.Principal.Kind != identity.Human {
		return zero, value.ErrDenied
	}
	recovery, err := s.Recovery.RecoveryState(ctx)
	if err != nil || !recovery.Valid(s.Now()) || recovery.InstallationID != s.InstallationID {
		return zero, value.ErrUnavailable
	}
	source, spec, err := s.Documents.ReadPolicy(ctx, name, "")
	if err != nil {
		return zero, s.refused("source", err)
	}
	if err = s.Sources.ObservePolicy(ctx, source); err != nil {
		return zero, s.refused("observe", err)
	}
	nonce := policyNonce(author.Principal, source.Revision.UID, key)
	if previous, found, err := s.Ledger.AcceptanceByNonce(ctx, nonce); err != nil {
		return zero, s.refused("nonce", err)
	} else if found {
		if previous.Submitter != author.Principal || previous.Authority.PolicyUID != source.Revision.UID {
			return zero, value.ErrConflict
		}
		// The original receipt is returned only while it is still the current
		// acceptance: a deactivated or replaced one is never reported active.
		if current, err := s.Ledger.Status(ctx, source.Revision.UID); err != nil {
			return zero, s.refused("status", err)
		} else if current.ActiveID != previous.ID {
			if current.DeactivatedID == previous.ID {
				return zero, ErrPolicyDeactivated
			}
			return zero, value.ErrConflict
		}
		audited := s.Audit.PublishPolicyAcceptances(ctx) == nil
		return PolicyActivationResult{PolicyUID: previous.Authority.PolicyUID, AcceptanceID: previous.ID, NotAfter: previous.Authority.NotAfter, MaxExecutions: previous.Authority.Limits.MaxExecutions, Replay: true, Audited: audited, Sharing: previous.Sharing}, nil
	}
	if source.Suspended || source.Deleted {
		return zero, value.ErrChanged
	}
	compiled, err := CompileRestartPolicy(spec, s.RecipeName, s.RecipeDigest)
	if s.CompileRecorder != nil {
		compiled, err = CompilePolicyWithRecorders(spec, s.RecipeName, s.RecipeDigest, s.CompileRecorder)
	}
	if err != nil {
		return zero, s.refused("compile", err)
	}
	// A probe policy observes its Events too, so a region that cannot read
	// them (or, for an alert policy, has no Alertmanager) refuses activation
	// instead of leaving the policy Unknown.
	observed, err := s.Observer.ObserveWorkloadRestarts(ctx, compiled.Request())
	if err != nil {
		return zero, s.refused("workload", err)
	}
	if active, err := s.Ledger.ActiveClusterPolicies(ctx, compiled.ClusterID, source.Revision.UID); err != nil {
		return zero, s.refused("count", err)
	} else if active >= value.MaxActivePoliciesPerCluster {
		return zero, value.ErrCapacity
	}
	status, err := s.Ledger.Status(ctx, source.Revision.UID)
	if err != nil {
		return zero, s.refused("status", err)
	}
	if compiled.Recorder != nil {
		return s.activateRecorderPolicy(ctx, author, recovery, source, compiled, observed, status, nonce, sharingReviewed)
	}
	target := authorization.Target{ClusterID: compiled.ClusterID, NamespaceUID: observed.Namespace.UID, WorkloadUID: observed.Workload.UID, PodUID: observed.Workload.UID}
	delegation, err := s.Ledger.Delegation(ctx, target)
	if err != nil {
		return zero, s.delegationRefused("basis")
	}
	projection, err := s.Permissions.Permissions(ctx, target)
	if err != nil {
		return zero, s.refused("permissions", err)
	}
	// Sponsors: the binding's current group maintainer assignments that the
	// submitter belongs to. They, not the submitter, carry later execution.
	var owners []artifact.AudienceAssignment
	for _, a := range projection.Allows {
		o := a.Audience
		if o.BasisKind == "AccessBinding" && o.BasisUID == delegation.UID && o.Kind == "Group" && o.Role == "workload-maintainer" && o.Issuer == author.Principal.Issuer && slices.Contains(author.Groups, o.SubjectID) {
			owners = append(owners, o)
		}
	}
	if len(owners) == 0 || len(owners) > 8 {
		return zero, s.delegationRefused("sponsors")
	}
	slices.SortFunc(owners, func(a, b artifact.AudienceAssignment) int {
		if a.AssignmentID < b.AssignmentID {
			return -1
		}
		if a.AssignmentID > b.AssignmentID {
			return 1
		}
		return 0
	})
	creator := author.Principal
	if status.Creator != nil {
		creator = *status.Creator
	}
	issued := s.Now().UTC().Truncate(time.Second)
	authority := authorization.AcceptedPolicyAuthority{InstallationID: s.InstallationID, PolicyUID: source.Revision.UID, Creator: creator, Executor: authorization.PolicyPrincipal(s.InstallationID, source.Revision.UID), ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, Delegation: delegation, Owners: owners, Actions: []string{authorization.PolicyContextAction}, Limits: authorization.AutomationLimits{MaxExecutions: 1, MaxBytes: 1}, IssuedAt: issued, NotAfter: issued.Add(time.Minute)}
	// The draft needs a nonzero scope to be well formed; the final scope below
	// replaces it.
	authority.ScopeDigest = RestartScopeDigest(source.Revision, source.CollectionDigest, compiled, target.NamespaceUID, target.WorkloadUID, delegation, owners, authority.Actions, authority.Limits)
	// The envelope is read through the accepted delegation: a minimal draft
	// selects it, then the policy takes the envelope's per-policy maxima.
	envelope, err := s.Automation.PolicyAutomationAuthority(ctx, authority, target)
	if err != nil {
		return zero, s.delegationRefused("envelope")
	}
	e := envelope.Envelope
	authority.Limits = authorization.AutomationLimits{MaxExecutions: e.MaxExecutions, MaxBytes: e.MaxBytes}
	authority.NotAfter = issued.Add(time.Duration(e.MaxLifetimeSeconds) * time.Second)
	if !envelope.NotAfter.IsZero() && envelope.NotAfter.Before(authority.NotAfter) {
		authority.NotAfter = envelope.NotAfter.UTC().Truncate(time.Second)
	}
	authority.ScopeDigest = RestartScopeDigest(source.Revision, source.CollectionDigest, compiled, target.NamespaceUID, target.WorkloadUID, delegation, owners, authority.Actions, authority.Limits)
	if !authority.Valid(s.Now()) {
		return zero, s.delegationRefused("authority")
	}
	if status.ActiveID != "" && status.Authority.ScopeDigest == authority.ScopeDigest {
		// This exact revision and delegation is already accepted; an unchanged
		// source can never be accepted again to reset its spend or expiry.
		audited := s.Audit.PublishPolicyAcceptances(ctx) == nil
		out := PolicyActivationResult{PolicyUID: authority.PolicyUID, AcceptanceID: status.ActiveID, NotAfter: status.NotAfter, MaxExecutions: status.MaxExecutions, Replay: true, Audited: audited}
		if status.Sharing != nil {
			out.Sharing = &status.Sharing.Instruction
		}
		return out, nil
	}
	if status.DeactivatedID != "" && status.Authority.ScopeDigest == authority.ScopeDigest {
		// Reactivation is a fresh acceptance of a changed scope (ADR-229): a
		// deactivated revision is never accepted again, so its spend and
		// expiry cannot be reset by stopping and starting it.
		return zero, ErrPolicyDeactivated
	}
	use := authorization.PolicyUse{PolicyUID: authority.PolicyUID, ScopeDigest: authority.ScopeDigest, Target: target, Purpose: authorization.PolicyIncident}
	if check := authorization.ValidatePolicyAcceptance(author, authority, envelope, use, s.Now()); !check.Eligible {
		return zero, s.delegationRefused("validate")
	}
	sharing, err := s.sharing(author, compiled.Sharing, projection, target, delegation.UID, owners, issued)
	if err != nil {
		return zero, s.refused("sharing", err)
	}
	if sharing != nil && !sharingReviewed {
		return zero, PolicySharingReview{Instruction: *sharing}
	}
	now := s.Now().UTC().Truncate(time.Microsecond)
	submission := value.VerifiedPolicySubmission{ReplacesID: status.ActiveID, Nonce: nonce, Actor: author.Principal, Source: source.Revision, ClusterID: source.ClusterID, NamespaceUID: source.NamespaceUID, Name: source.Name, ScopeDigest: authority.ScopeDigest, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second)}
	submitted, _ := json.Marshal(submission)
	submission.EnvelopeDigest = artifact.Digest(sha256.Sum256(submitted))
	until := identity.Earlier(identity.Earlier(now.Add(5*time.Second), author.ValidUntil), recovery.FreshUntil)
	check := value.SubmissionCheck{Submission: submission, RootID: s.RootID, InstallationID: s.InstallationID, IssuerEpoch: recovery.IssuerEpoch, KeyID: "hub-api-authenticated-session", TrustRevision: author.Policy, VerifiedAt: now, ValidUntil: until.UTC().Truncate(time.Microsecond)}
	call, cancel := context.WithDeadline(ctx, check.ValidUntil)
	defer cancel()
	accepted, err := s.Acceptor.AcceptPolicy(call, value.PolicyAdmission{RootID: s.RootID, Submission: submission, Verification: check, Author: author, Authority: authority, Target: target, Recovery: recovery, Sharing: sharing})
	if err != nil {
		return zero, s.refused("accept", err)
	}
	// Acceptance is not eligible until its encrypted audit is acknowledged; a
	// failure here leaves it pending for the trigger loop's publisher.
	audited := s.Audit.PublishPolicyAcceptances(ctx) == nil
	r := accepted.Record
	return PolicyActivationResult{PolicyUID: r.Authority.PolicyUID, AcceptanceID: r.ID, NotAfter: r.Authority.NotAfter, MaxExecutions: r.Authority.Limits.MaxExecutions, Replay: accepted.Replay, Audited: audited, Sharing: r.Sharing}, nil
}

// sharing resolves a policy's spec.sharing into the accepted instruction
// (ADR-239). The activating human needs the create_share authority on the
// workload (evidence:share, no deny) through an evidence-owner Group
// assignment of the automation AccessBinding for a sponsoring group: those
// assignments are the policy's owner teams and manage every share. The end
// must be in the future and at most seven days after activation, as for any
// share. Without sharing, nothing is resolved.
func (s PolicyActivation) sharing(author identity.Identity, in *value.PolicySharing, p authorization.Projection, target authorization.Target, delegation string, sponsors []artifact.AudienceAssignment, issued time.Time) (*value.PolicyShareInstruction, error) {
	if in == nil {
		return nil, nil
	}
	if in.Recipients[0].Issuer != author.Principal.Issuer || !in.NotAfter.After(s.Now()) || in.NotAfter.After(issued.Add(authorization.ShareMaxLifetime)) {
		return nil, value.PolicyFieldError{Path: "spec.sharing.notAfter", Reason: "must be in the future and at most seven days after activation, with recipients of your issuer"}
	}
	var groups []string
	for _, o := range sponsors {
		groups = append(groups, o.SubjectID)
	}
	result, management := authorization.PolicyShareManagement(author, p, target, delegation, groups, s.Now())
	if !result.Eligible {
		if s.Report != nil {
			s.Report("sharing/" + result.Reason)
		}
		return nil, value.ErrSharingDenied
	}
	out := value.PolicyShareInstruction{Creator: author.Principal, Management: management, Recipients: slices.Clone(in.Recipients), MaxCaptures: in.MaxCaptures, NotAfter: in.NotAfter.UTC()}
	if !out.Valid() {
		return nil, value.ErrInvalid
	}
	return &out, nil
}
