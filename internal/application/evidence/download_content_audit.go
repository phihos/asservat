package evidence

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"time"
)

// This closed outcome concerns only authenticated metadata/conditional
// preflight. It never says that a subsequent response reached client storage;
// the existing response/window audit owns body accounting.
type DownloadContentStatus string

const (
	DownloadContentReady        DownloadContentStatus = "ready"
	DownloadContentNotModified  DownloadContentStatus = "not-modified"
	DownloadContentPrecondition DownloadContentStatus = "precondition-failed"
	DownloadContentRange        DownloadContentStatus = "range-unsatisfiable"
	DownloadContentInvalid      DownloadContentStatus = "invalid"
	DownloadContentDenied       DownloadContentStatus = "denied"
	DownloadContentUnavailable  DownloadContentStatus = "unavailable"
)

func (s DownloadContentStatus) Valid() bool {
	switch s {
	case DownloadContentReady, DownloadContentNotModified, DownloadContentPrecondition, DownloadContentRange, DownloadContentInvalid, DownloadContentDenied, DownloadContentUnavailable:
		return true
	}
	return false
}

type DownloadContentAuditor interface {
	BeginDownloadContent(context.Context, identities.CurrentIdentity, DownloadResponseRequest) (DownloadContentAudit, error)
}
type DownloadContentAudit interface {
	Deadline() time.Time
	Finish(context.Context, DownloadContentStatus) (time.Time, error)
	Close()
}

// The HTTP selection adapter supplies a fixed classification without passing
// headers or native facts into the audit coordinator. The original local error
// remains available to that request's transport, after successful audit only.
type DownloadContentSelectionError struct {
	Status DownloadContentStatus
	Cause  error
}

func (e *DownloadContentSelectionError) Error() string { return "native content preflight declined" }
func (e *DownloadContentSelectionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}
func contentStatus(err error) DownloadContentStatus {
	if err == nil {
		return DownloadContentReady
	}
	var condition *DownloadContentSelectionError
	if errors.As(err, &condition) && condition.Status.Valid() {
		return condition.Status
	}
	if errors.Is(err, artifact.ErrInvalid) {
		return DownloadContentInvalid
	}
	if errors.Is(err, identity.ErrDenied) {
		return DownloadContentDenied
	}
	return DownloadContentUnavailable
}

// Only the authenticated HTTP adapter consumes this notification. It permits
// a metadata-only conditional reply within the still-original audit interval,
// not a body write or another reservation. Body writes retain byte leases.
type DownloadContentPreflightReceiver interface{ DownloadContentPreflightComplete(time.Time) }

// A successful preflight may enter a bounded no-output body setup phase. This
// changes only the socket idle bound; it grants neither identity nor bytes.
// Conditional and failed preflights never enter this phase.
type DownloadContentBodyReceiver interface {
	BeginDownloadContentBody(context.Context, time.Time) error
}
