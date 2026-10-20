package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

type DownloadPolicyReader interface {
	DownloadPolicy(context.Context) (privacy.DownloadPolicy, error)
}
type DownloadRecoveryReader interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}
type DownloadProcessingReader interface {
	ContextProcessing(context.Context, ContextDownloadEvidence, artifact.RecoveryProof) (artifact.DownloadProcessingProof, error)
}

// CurrentDownloadEnvironment composes protected deployment policy with actual
// recovery and complete durable processing decisions. It never supplies a
// region default, infers processing approval from storage registration, or
// resolves another principal from a token. Browser and MCP use the same service.
type CurrentDownloadEnvironment struct {
	RootID, InstallationID string
	Policies               DownloadPolicyReader
	Recovery               DownloadRecoveryReader
	Processing             DownloadProcessingReader
	Now                    func() time.Time
}

var _ DownloadEnvironmentReader = CurrentDownloadEnvironment{}

func (s CurrentDownloadEnvironment) DownloadEnvironment(ctx context.Context, r ContextDownloadEvidence, actor identity.Principal) (artifact.DownloadEnvironment, error) {
	var zero artifact.DownloadEnvironment
	if ctx == nil || ctx.Err() != nil || s.Policies == nil || s.Recovery == nil || s.Processing == nil || s.Now == nil || !actor.Valid() || !r.Retained.Valid() || r.Retained.RootID != s.RootID || !identity.Text(r.PurposeRef, 128) || r.Retained.Input.EvidenceType != "context" || r.Retained.Input.PrivacyClass != "potentialPersonalData" {
		return zero, artifact.ErrDownloadUnavailable
	}
	start := s.Now()
	until := identity.Earlier(start.Add(5*time.Second), identity.Earlier(r.ValidUntil, r.Retained.Effective.ExpiresAt))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	if !identity.Fresh(r.ObservedAt, r.ValidUntil, start, 5*time.Second) || !start.Before(until) {
		return zero, artifact.ErrDownloadExpired
	}
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	p, e := s.Policies.DownloadPolicy(call)
	if e != nil || !p.DownloadValid(s.Now()) || p.RootID != s.RootID || p.InstallationID != s.InstallationID {
		return zero, artifact.ErrDownloadUnavailable
	}
	path, ok := p.SelectDownload(actor, r.Retained.Input.Target.ClusterID, r.Retained.Registration.StoreID, r.PurposeRef, "metadata", r.Retained.Input.PrivacyClass, r.Retained.Input.EvidenceType, s.Now())
	if !ok {
		return zero, artifact.ErrDownloadUnavailable
	}
	until = identity.Earlier(until, p.FreshUntil)
	// Nested contexts only shorten. A later source observation cannot renew the
	// original catalog, policy, request or recovery deadline.
	call, stopPolicy := context.WithDeadline(call, until)
	defer stopPolicy()
	recovery, e := s.Recovery.RecoveryState(call)
	if e != nil || !recovery.Valid(s.Now()) || recovery.InstallationID != s.InstallationID || recovery.IssuerEpoch != p.RecoveryEpoch {
		return zero, artifact.ErrDownloadUnavailable
	}
	until = identity.Earlier(until, recovery.FreshUntil)
	call, stopRecovery := context.WithDeadline(call, until)
	defer stopRecovery()
	processing, e := s.Processing.ContextProcessing(call, r, recovery)
	if e != nil || !processing.Valid(s.Now()) || processing.RootID != s.RootID || processing.CaptureID != r.CaptureID || processing.Location != r.Retained.Registration.Location {
		return zero, artifact.ErrDownloadUnavailable
	}
	until = identity.Earlier(until, processing.ValidUntil)
	call, stopProcessing := context.WithDeadline(call, until)
	defer stopProcessing()
	last, e := s.Policies.DownloadPolicy(call)
	if e != nil || !last.DownloadValid(s.Now()) || last.RootID != p.RootID || last.InstallationID != p.InstallationID || last.RecoveryEpoch != p.RecoveryEpoch || last.Revision != p.Revision || last.ProtectionDigest != p.ProtectionDigest {
		return zero, artifact.ErrDownloadUnavailable
	}
	lastPath, ok := last.SelectDownload(actor, r.Retained.Input.Target.ClusterID, r.Retained.Registration.StoreID, r.PurposeRef, "metadata", r.Retained.Input.PrivacyClass, r.Retained.Input.EvidenceType, s.Now())
	if !ok || lastPath != path {
		return zero, artifact.ErrDownloadUnavailable
	}
	until = identity.Earlier(until, last.FreshUntil)
	lastRecovery, e := s.Recovery.RecoveryState(call)
	if e != nil || !lastRecovery.Valid(s.Now()) || lastRecovery.InstallationID != recovery.InstallationID || lastRecovery.IssuerEpoch != recovery.IssuerEpoch || lastRecovery.Revision != recovery.Revision {
		return zero, artifact.ErrDownloadUnavailable
	}
	until = identity.Earlier(until, lastRecovery.FreshUntil)
	lastProcessing, e := s.Processing.ContextProcessing(call, r, recovery)
	if e != nil || !lastProcessing.Valid(s.Now()) || lastProcessing.RootID != processing.RootID || lastProcessing.Epoch != processing.Epoch || lastProcessing.Sequence != processing.Sequence || lastProcessing.CaptureID != processing.CaptureID || lastProcessing.Location != processing.Location || lastProcessing.StateDigest != processing.StateDigest {
		return zero, artifact.ErrDownloadUnavailable
	}
	until = identity.Earlier(until, lastProcessing.ValidUntil)
	// Full policy identity includes the durable processing version and the
	// selected path. Observation timestamps remain separate runtime bounds.
	b, e := json.Marshal(struct {
		Policy   identity.Revision
		Guard    artifact.Digest
		Path     artifact.DownloadPath
		Epoch    string
		Sequence int64
		State    artifact.Digest
	}{p.Revision, p.ProtectionDigest, path, processing.Epoch, processing.Sequence, processing.StateDigest})
	if e != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	policy := p.Revision
	policy.Digest = sha256.Sum256(b)
	out := artifact.DownloadEnvironment{RootID: s.RootID, InstallationID: s.InstallationID, Region: path.AcquisitionRegion, StoreID: r.Retained.Registration.StoreID, RecoveryEpoch: recovery.IssuerEpoch, Location: r.Retained.Registration.Location, Principal: actor, Revision: policy, RecoveryRevision: recovery.Revision, Path: path, Processing: processing, ObservedAt: start, ValidUntil: until}
	if call.Err() != nil || !out.CurrentValid(s.Now()) || !p.DownloadValid(s.Now()) || !recovery.Valid(s.Now()) || !processing.Valid(s.Now()) {
		return zero, artifact.ErrDownloadExpired
	}
	return out, nil
}
