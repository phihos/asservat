package execution

import (
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const (
	GoProfileMediaType          = artifact.ProfileMediaType
	DefaultGoProfileBytes int64 = 16 << 20
	MaximumGoProfileBytes       = artifact.MaxPprofBytes
	DefaultGoTraceBytes   int64 = 32 << 20
	MaximumGoTraceBytes         = artifact.MaxGoTraceBytes
)

var (
	ErrProfileUnavailable = errors.New("profile endpoint unavailable")
	ErrProfilerBusy       = errors.New("application profiler already active")
	ErrProfileLimit       = errors.New("profile output limit exceeded")
	ErrProfileOutput      = errors.New("profile encrypted output incomplete")
)

// GoProfileParameters is the finite HTTP pprof subset of the existing profile
// action. It cannot enable sampling, change its frequency or select a URL.
// Defaults belong to preview/planning; execution never silently supplies them.
type GoProfileParameters struct {
	Type, Mode string
	Duration   time.Duration
	ForceGC    bool
}

func (p GoProfileParameters) Valid() bool {
	return artifact.ValidGoProfile(p.Type, p.Mode, p.Duration, p.ForceGC)
}

func (p GoProfileParameters) Format() string {
	if p.Type == "runtimeTrace" {
		return artifact.GoTraceFormat
	}
	return artifact.PprofFormat
}

// GoProfileRequest is an already resolved mechanism input, not a public request
// or authority. The caller must first commit intrusive-action admission, the
// local start journal, mutually exclusive runtime-domain spend and ciphertext
// custody. EndpointDigest covers the resolved template, endpoint, credential
// audience and parameters. Neither changing a delivery ID nor retrying this
// mechanism may create a new permission to start.
type GoProfileRequest struct {
	Binding             artifact.Binding
	Pin                 artifact.PinnedPod
	NodeUID, NodeBootID string
	SourceRef           string
	EndpointDigest      artifact.Digest
	Parameters          GoProfileParameters
	NativeLimit         int64
	NotBefore, Deadline time.Time
}

func (r GoProfileRequest) Validate(now time.Time) error {
	if r.Binding.Validate() != nil || r.Binding.MediaType != GoProfileMediaType || !r.Parameters.Valid() || !identity.Text(r.SourceRef, 63) || r.EndpointDigest == (artifact.Digest{}) {
		return ErrInvalid
	}
	for _, id := range []string{r.Pin.UID, r.Pin.NamespaceUID, r.NodeUID, r.NodeBootID} {
		if !authorization.UUID(id) {
			return ErrInvalid
		}
	}
	if r.Pin.ControllerUID != "" && !authorization.UUID(r.Pin.ControllerUID) {
		return ErrInvalid
	}
	if !identity.Text(r.Pin.Namespace, 63) || !identity.Text(r.Pin.Name, 253) || !identity.Text(r.Pin.NodeName, 253) || !canonicalTime(r.NotBefore) || !canonicalTime(r.Deadline) {
		return ErrInvalid
	}
	cap := MaximumGoProfileBytes
	if r.Parameters.Type == "runtimeTrace" {
		cap = MaximumGoTraceBytes
	}
	// Two seconds of explicit setup/shutdown margin must fit in the original
	// action interval. Planning may choose more, up to ten seconds. Snapshot
	// actions have a hard ten-second mechanism ceiling (default remains five).
	maxInterval := r.Parameters.Duration + 10*time.Second
	if r.NativeLimit < 1 || r.NativeLimit > cap || r.Deadline.Sub(r.NotBefore) > maxInterval || r.Deadline.Sub(r.NotBefore) < r.Parameters.Duration+2*time.Second {
		return ErrInvalid
	}
	if now.Before(r.NotBefore) || !now.Before(r.Deadline) {
		return ErrExpired
	}
	return nil
}

// GoProfileCurrent is a fresh observation by the purpose-specific current
// authority guard. It does not refresh the admitted request, retention anchor,
// endpoint digest, runtime-domain slot or action deadline.
type GoProfileCurrent struct{ CheckedAt, ValidUntil time.Time }

func (o GoProfileCurrent) Valid(r GoProfileRequest, now time.Time) bool {
	return r.Validate(now) == nil && identity.Fresh(o.CheckedAt, o.ValidUntil, now, 5*time.Second) && !o.ValidUntil.After(r.Deadline)
}

// GoProfileOutcome describes acquisition only. ResponseComplete is neither a
// valid parsed profile nor custody commit/catalog publication. Process identity,
// sampling configuration and remote stop remain unknown without independent
// qualified observations, even after the HTTP body reaches EOF.
type GoProfileOutcome struct {
	Format                           string
	StartedAt, CompletedAt           time.Time
	MayHaveStarted, ResponseComplete bool
	NativeBytes                      int64
}
