package capture

import (
	"context"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
)

// CaptureRequest submits a reviewed preview (ADR-330 D9). Preview recomputes
// the plan under the request's plan scope; a plan whose digest differs from
// Plan is ReviewChanged. The same requester, key and plan always name the
// same capture, so a retry never collects twice.
type CaptureRequest struct {
	Key     string
	Plan    artifact.Digest
	Access  *authorization.ResultAccess
	Preview func(context.Context) (value.ContextPreview, error)
}

// ContextAdmissionReplay is a read-only transaction with current SQL target
// permissions/denies after locks. Lookup precedes the preview, permitting
// exact accepted replay after the target disappeared. A changed digest under
// the same actor/client/key conflicts. Missing is the only result that
// permits a new preview-to-admission attempt.
type ContextAdmissionReplay interface {
	LookupContextAdmission(context.Context, value.ReplayQuery) (value.Accepted, bool, error)
}

// ReviewedAdmissionTransaction admits one reviewed plan under the request ID
// its requester, key and plan digest derive.
type ReviewedAdmissionTransaction interface {
	AdmitReviewedContext(context.Context, value.ContextPreview, value.Admission) (value.Accepted, error)
}
