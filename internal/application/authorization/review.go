package authorization

import (
	"context"
	"errors"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// AccessReviewer is the target cluster's connector (ADR-245): it maps the
// principal through its own identity mapping and submits one
// SubjectAccessReview. A transport or connector failure is an error; a
// closed negative decision is an answer.
type AccessReviewer interface {
	ReviewAccess(context.Context, targets.AccessReviewRequest) (targets.AccessReviewAnswer, error)
}

// RecordedReview is one principal's recorded review target for one source:
// the exact Pod attributes it was first reviewed with.
type RecordedReview struct {
	SourceUID string
	Target    targets.Request
}

// ReviewDecision is one review outcome to record. DecidedAt is taken before
// the connector was asked, so the positive decision cannot outlive its own
// question.
type ReviewDecision struct {
	Source    configuration.ReviewSource
	Principal identity.Principal
	Target    targets.Request
	Allowed   bool
	// Outcome is the connector's closed outcome, or "Unavailable" when no
	// answer arrived; it is the audited reason of a decision change.
	Outcome   string
	DecidedAt time.Time
}

// AccessReviewStore persists decision-time assignments (ADR-245). Recording
// an allowed decision mints the principal's assignment for the source once and
// makes it visible, for this Pod, to every permission projection until the
// decision's lifetime ends; recording a refusal ends that lifetime at once.
type AccessReviewStore interface {
	ReviewSources(context.Context, string) ([]configuration.ReviewSource, error)
	RecordedReviews(context.Context, identity.Principal, value.Target) ([]RecordedReview, error)
	// RecordedCaptureReviews returns the principal's recorded reviews of the
	// Pod of one capture, whoever created it; nothing else of the capture.
	RecordedCaptureReviews(context.Context, identity.Principal, string) ([]RecordedReview, error)
	// RecordedPreviewReviews returns the principal's recorded reviews of the
	// Pod of one of its own previews, closed or not.
	RecordedPreviewReviews(context.Context, identity.Principal, string) ([]RecordedReview, error)
	RecordReview(context.Context, ReviewDecision) error
}

// RecordedReviewRefresher repeats a principal's recorded decision-time
// reviews of one target before a read path reads permissions (ADR-245). A
// nil refresher leaves decision-time sources out of that path.
type RecordedReviewRefresher interface {
	ReviewRecorded(context.Context, identity.Identity, value.Target) error
}

// ResolvedReviewer reviews a live, freshly resolved Pod (capture and
// explanation paths).
type ResolvedReviewer interface {
	ReviewResolved(context.Context, identity.Identity, targets.Request) error
}

// AccessReviews performs the request-time reviews of the decision-time
// PermissionSources (REQ-PER-004): one SubjectAccessReview per accepted
// source of the target's cluster, by the target cluster's connector, for the
// request's current authenticated human principal. It grants nothing by
// itself: an allowed review is recorded and then appears as an ordinary
// Reviewed allow in the permission projection, where denies still win and
// every evaluator check applies. It never runs for a policy or workload
// principal (human-only exec inheritance supplies no automation delegation).
type AccessReviews struct {
	Store    AccessReviewStore
	Reviewer AccessReviewer
	Now      func() time.Time
}

// ReviewResolved reviews a live, freshly resolved Pod: the capture and
// explanation paths, before their permission read.
func (s AccessReviews) ReviewResolved(ctx context.Context, i identity.Identity, target targets.Request) error {
	if !s.configured() || i.Principal.Kind != identity.Human || !target.Valid() {
		return nil
	}
	sources, err := s.Store.ReviewSources(ctx, target.ClusterID)
	if err != nil {
		return err
	}
	var errs []error
	for _, src := range sources {
		errs = append(errs, s.review(ctx, i, src, target))
	}
	return errors.Join(errs...)
}

// ReviewRecorded repeats the review of the principal's recorded attributes of
// target: the read paths, before their permission read. A fresh review is
// made on every call; the recorded name lets a deleted Pod be reviewed
// (REQ-PER-008), while the connector refuses a same-name replacement.
func (s AccessReviews) ReviewRecorded(ctx context.Context, i identity.Identity, target value.Target) error {
	if !s.configured() || i.Principal.Kind != identity.Human || !target.Valid() {
		return nil
	}
	recorded, err := s.Store.RecordedReviews(ctx, i.Principal, target)
	if err != nil {
		return err
	}
	return s.repeat(ctx, i, target.ClusterID, recorded, func(r targets.Request) bool {
		return r.ClusterID == target.ClusterID && r.Namespace.UID == target.NamespaceUID && r.Workload.UID == target.WorkloadUID && r.PodUID == target.PodUID
	})
}

// ReviewCapture repeats the principal's recorded reviews of one capture's Pod:
// the capture status path, which names only the capture.
func (s AccessReviews) ReviewCapture(ctx context.Context, i identity.Identity, captureID string) error {
	if !s.configured() || i.Principal.Kind != identity.Human || !value.UUID(captureID) {
		return nil
	}
	recorded, err := s.Store.RecordedCaptureReviews(ctx, i.Principal, captureID)
	if err != nil || len(recorded) == 0 {
		return err
	}
	return s.repeat(ctx, i, recorded[0].Target.ClusterID, recorded, func(r targets.Request) bool { return r == recorded[0].Target })
}

// ReviewPreview repeats the principal's recorded reviews of the Pod of one of
// its previews: request resolution, which names only the preview.
func (s AccessReviews) ReviewPreview(ctx context.Context, i identity.Identity, previewID string) error {
	if !s.configured() || i.Principal.Kind != identity.Human || !value.UUID(previewID) {
		return nil
	}
	recorded, err := s.Store.RecordedPreviewReviews(ctx, i.Principal, previewID)
	if err != nil || len(recorded) == 0 {
		return err
	}
	return s.repeat(ctx, i, recorded[0].Target.ClusterID, recorded, func(r targets.Request) bool { return r == recorded[0].Target })
}

func (s AccessReviews) repeat(ctx context.Context, i identity.Identity, cluster string, recorded []RecordedReview, matches func(targets.Request) bool) error {
	if len(recorded) == 0 {
		return nil
	}
	sources, err := s.Store.ReviewSources(ctx, cluster)
	if err != nil {
		return err
	}
	var errs []error
	for _, r := range recorded {
		for _, src := range sources {
			if src.Resource.UID == r.SourceUID && matches(r.Target) {
				errs = append(errs, s.review(ctx, i, src, r.Target))
			}
		}
	}
	return errors.Join(errs...)
}

func (s AccessReviews) configured() bool {
	return s.Store != nil && s.Reviewer != nil && s.Now != nil
}

// review asks the connector once and records the outcome. A connector or
// transport failure is recorded as a refusal: a SAR outage denies the source
// (SC-PER-006) and ends an earlier positive decision instead of letting it
// run out.
func (s AccessReviews) review(ctx context.Context, i identity.Identity, src configuration.ReviewSource, target targets.Request) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request := targets.ReviewRequest(src, target, i.Principal.Issuer, i.Principal.Subject, i.Groups)
	decided := s.Now().UTC().Truncate(time.Microsecond)
	answer, err := s.Reviewer.ReviewAccess(call, request)
	outcome := "Unavailable"
	if err == nil && answer.Valid(request) {
		outcome = answer.Outcome
	}
	allowed := outcome == targets.AccessAllowed && i.Valid(s.Now())
	if outcome == targets.AccessAllowed && !allowed {
		outcome = "IdentityUnavailable"
	}
	if e := s.Store.RecordReview(ctx, ReviewDecision{Source: src, Principal: i.Principal, Target: target, Allowed: allowed, Outcome: outcome, DecidedAt: decided}); e != nil {
		return errors.Join(err, e)
	}
	return err
}
