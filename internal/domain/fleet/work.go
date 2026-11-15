// Package fleet defines bounded hub/connector control values.
package fleet

import "errors"

var (
	ErrInvalid     = errors.New("invalid control work")
	ErrUnavailable = errors.New("control work unavailable")
	ErrDenied      = errors.New("control work rejected")
	ErrUnsupported = errors.New("control purpose or capability unsupported")
	ErrPending     = errors.New("enrollment is pending")
	ErrCapacity    = errors.New("fleet enrollment limit reached")
	ErrConflict    = errors.New("enrollment request conflicts with its original identity")
	// ErrLocalBootstrapConsumed: the installation's own connector claimed its
	// latest local bootstrap slot; no further local slot is reserved.
	ErrLocalBootstrapConsumed = errors.New("local cluster bootstrap consumed")
)
