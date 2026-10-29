package capture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

type policyWorkloadDelegation interface {
	WorkloadDelegation(context.Context, authorization.WorkloadTarget) (identity.Revision, error)
}

func (s PolicyActivation) activateRecorderPolicy(ctx context.Context, author identity.Identity, recovery artifact.RecoveryProof, source value.PolicySource, compiled value.RestartPolicy, observed targets.RestartObservation, status value.PolicyStatus, nonce string, sharingReviewed bool) (PolicyActivationResult, error) {
	var zero PolicyActivationResult
	ledger, ok := s.Ledger.(policyWorkloadDelegation)
	now := s.Now()
	if !ok || s.WorkloadAutomation == nil || !source.Valid(now) || !observed.Valid(now) || !observed.Answers(compiled.Request()) || observed.ClusterID != compiled.ClusterID || observed.Namespace.Name != compiled.Namespace || observed.Workload.Kind != compiled.WorkloadKind || observed.Workload.Name != compiled.WorkloadName || status.PolicyUID != source.Revision.UID || status.IntentVersion < 1 {
		return zero, s.refused("recorder/workload", value.ErrUnavailable)
	}
	target := authorization.WorkloadTarget{ClusterID: observed.ClusterID, NamespaceUID: observed.Namespace.UID, WorkloadUID: observed.Workload.UID}
	delegation, err := ledger.WorkloadDelegation(ctx, target)
	if err != nil {
		return zero, s.delegationRefused("basis")
	}
	envelope, err := s.WorkloadAutomation.PolicyWorkloadAutomation(ctx, target, delegation)
	if err != nil {
		return zero, s.delegationRefused("envelope")
	}
	// One existing current envelope read also carries the complete accepted
	// workload permissions. There is no second read or invented draft authority.
	var owners []artifact.AudienceAssignment
	for _, a := range envelope.Permissions.Allows {
		o := a.Audience
		if !a.Reviewed && o.BasisKind == "AccessBinding" && o.BasisUID == delegation.UID && o.Kind == "Group" && o.Role == "workload-maintainer" && o.Issuer == author.Principal.Issuer && slices.Contains(author.Groups, o.SubjectID) {
			owners = append(owners, o)
		}
	}
	if len(owners) == 0 || len(owners) > 8 {
		return zero, s.delegationRefused("sponsors")
	}
	slices.SortFunc(owners, func(a, b artifact.AudienceAssignment) int { return strings.Compare(a.AssignmentID, b.AssignmentID) })
	creator := author.Principal
	if status.Creator != nil {
		creator = *status.Creator
	}
	issued := s.Now().UTC().Truncate(time.Second)
	authority := authorization.AcceptedPolicyAuthority{InstallationID: s.InstallationID, PolicyUID: source.Revision.UID, Creator: creator, Executor: authorization.PolicyPrincipal(s.InstallationID, source.Revision.UID), ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, Delegation: delegation, Owners: owners, Actions: []string{"packetCapture"}, Limits: authorization.AutomationLimits{MaxExecutions: envelope.Envelope.MaxExecutions, MaxBytes: envelope.Envelope.MaxBytes, MaxObservedBytes: envelope.Envelope.MaxObservedBytes}, IssuedAt: issued, NotAfter: issued.Add(time.Duration(envelope.Envelope.MaxLifetimeSeconds) * time.Second)}
	if !envelope.NotAfter.IsZero() {
		authority.NotAfter = identity.Earlier(authority.NotAfter, envelope.NotAfter.UTC().Truncate(time.Second))
	}
	authority.ScopeDigest = RecorderPolicyScopeDigest(source.Revision.UID, status.IntentVersion, source.CollectionDigest, compiled, target.NamespaceUID, target.WorkloadUID, delegation, owners, authority.Actions, authority.Limits)
	check := authorization.ValidatePolicyWorkloadAcceptance(author, authority, envelope, s.Now())
	if !check.Eligible {
		return zero, s.delegationRefused("validate")
	}
	if status.ActiveID != "" && status.Authority.ScopeDigest == authority.ScopeDigest {
		audited := s.Audit.PublishPolicyAcceptances(ctx) == nil
		out := PolicyActivationResult{PolicyUID: authority.PolicyUID, AcceptanceID: status.ActiveID, NotAfter: status.NotAfter, MaxExecutions: status.MaxExecutions, Replay: true, Audited: audited}
		if status.Sharing != nil {
			out.Sharing = &status.Sharing.Instruction
		}
		return out, nil
	}
	if status.DeactivatedID != "" && status.Authority.ScopeDigest == authority.ScopeDigest {
		return zero, ErrPolicyDeactivated
	}
	var sharing *value.PolicyShareInstruction
	if in := compiled.Sharing; in != nil {
		if in.Recipients[0].Issuer != author.Principal.Issuer || !in.NotAfter.After(s.Now()) || in.NotAfter.After(issued.Add(authorization.ShareMaxLifetime)) {
			return zero, value.PolicyFieldError{Path: "spec.sharing.notAfter", Reason: "must be in the future and at most seven days after activation, with recipients of your issuer"}
		}
		var sponsors []string
		for _, owner := range owners {
			sponsors = append(sponsors, owner.SubjectID)
		}
		result, management := authorization.PolicyWorkloadShareManagement(author, envelope.Permissions, target, delegation.UID, sponsors, s.Now())
		if !result.Eligible {
			return zero, value.ErrSharingDenied
		}
		sharing = &value.PolicyShareInstruction{Creator: author.Principal, Management: management, Recipients: slices.Clone(in.Recipients), MaxCaptures: in.MaxCaptures, NotAfter: in.NotAfter.UTC()}
		if !sharing.Valid() {
			return zero, value.ErrInvalid
		}
		if !sharingReviewed {
			return zero, PolicySharingReview{Instruction: *sharing}
		}
	}
	now = s.Now().UTC().Truncate(time.Microsecond)
	submission := value.VerifiedPolicySubmission{ReplacesID: status.ActiveID, Nonce: nonce, Actor: author.Principal, Source: source.Revision, ClusterID: source.ClusterID, NamespaceUID: source.NamespaceUID, Name: source.Name, ScopeDigest: authority.ScopeDigest, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second)}
	raw, _ := json.Marshal(submission)
	submission.EnvelopeDigest = artifact.Digest(sha256.Sum256(raw))
	until := identity.Earlier(now.Add(5*time.Second), author.ValidUntil)
	for _, bound := range []time.Time{recovery.FreshUntil, source.FreshUntil, observed.FreshUntil, check.ValidUntil} {
		until = identity.Earlier(until, bound)
	}
	verification := value.SubmissionCheck{Submission: submission, RootID: s.RootID, InstallationID: s.InstallationID, IssuerEpoch: recovery.IssuerEpoch, KeyID: "hub-api-authenticated-session", TrustRevision: author.Policy, VerifiedAt: now, ValidUntil: until.UTC().Truncate(time.Microsecond)}
	if ctx.Err() != nil || !now.Before(until) {
		return zero, value.ErrChanged
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	accepted, err := s.Acceptor.AcceptPolicy(call, value.PolicyAdmission{RootID: s.RootID, Submission: submission, Verification: verification, Author: author, Authority: authority, Workload: &target, Recovery: recovery, Sharing: sharing})
	if err != nil {
		return zero, s.refused("accept", err)
	}
	audited := s.Audit.PublishPolicyAcceptances(ctx) == nil
	r := accepted.Record
	return PolicyActivationResult{PolicyUID: r.Authority.PolicyUID, AcceptanceID: r.ID, NotAfter: r.Authority.NotAfter, MaxExecutions: r.Authority.Limits.MaxExecutions, Replay: accepted.Replay, Audited: audited, Sharing: r.Sharing}, nil
}
