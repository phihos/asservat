package collector

import (
	"net/netip"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/execution"
)

// ProfileCapture is one already admitted Go endpoint attempt. It carries no
// credential or evidence key. Endpoint and definition digests are resolved by
// the connector from its protected configuration and the exact Pod; the node
// still binds the local network namespace before connecting.
type ProfileCapture struct {
	CaptureID         string
	ExpectationDigest artifact.Digest
	DefinitionDigest  artifact.Digest
	CollectorEpoch    string
	Request           execution.GoProfileRequest
	AddressMode       string
	Address           netip.Addr
	Port              uint16
	Host              string
}

func (p ProfileCapture) Valid() bool {
	if !authorization.UUID(p.CaptureID) || !authorization.UUID(p.CollectorEpoch) || p.ExpectationDigest == (artifact.Digest{}) || p.DefinitionDigest == (artifact.Digest{}) || p.Request.Validate(p.Request.NotBefore) != nil || p.Port == 0 || len(p.Host) == 0 || len(p.Host) > 253 || strings.ContainsAny(p.Host, "/\\?#@%\r\n\t ") || !p.Address.IsValid() || p.Address.Zone() != "" || p.Address.Is4In6() {
		return false
	}
	for _, b := range []byte(p.Host) {
		if b < 33 || b > 126 {
			return false
		}
	}
	switch p.AddressMode {
	case "targetLoopback":
		return p.Address.IsLoopback()
	case "podIP":
		return p.Address.IsGlobalUnicast() && !p.Address.IsLoopback() && !p.Address.IsLinkLocalUnicast()
	}
	return false
}

// ProfileResult is acquisition provenance, never a semantic verification or
// custody verdict. Failed or uncertain acquisitions may report zero bytes.
type ProfileResult struct {
	WorkID, CaptureID string
	ExpectationDigest artifact.Digest
	EndpointDigest    artifact.Digest
	Outcome           execution.GoProfileOutcome
	Failure           Reason
}

func (r ProfileResult) Valid() bool {
	o := r.Outcome
	if !authorization.UUID(r.WorkID) || !authorization.UUID(r.CaptureID) || r.ExpectationDigest == (artifact.Digest{}) || r.EndpointDigest == (artifact.Digest{}) || o.NativeBytes < 0 || o.NativeBytes > artifact.MaxGoTraceBytes || o.CompletedAt.IsZero() || (!o.StartedAt.IsZero() && (o.CompletedAt.Before(o.StartedAt) || o.CompletedAt.Sub(o.StartedAt) > 2*time.Minute)) || (o.StartedAt.IsZero() && o.MayHaveStarted) || (o.Format != artifact.PprofFormat && o.Format != artifact.GoTraceFormat) {
		return false
	}
	if r.Failure == "" {
		return !o.StartedAt.IsZero() && o.ResponseComplete && o.MayHaveStarted && o.NativeBytes > 0
	}
	return !o.ResponseComplete && (r.Failure == ReasonCaptureFailed || r.Failure == ReasonTargetNotFound || r.Failure == ReasonTargetHostNet || r.Failure == ReasonCaptureBusy)
}
