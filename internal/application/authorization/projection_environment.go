package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type ContextProjectionPolicyReader interface {
	ContextProjectionPolicy(context.Context, string, string) (value.ContextProjectionPolicy, error)
}
type ContextProjectionProcessingReader interface {
	ContextProjectionProcessing(context.Context, ContextProjectionEvidence, artifact.RecoveryProof) (artifact.DownloadProcessingProof, error)
}

// CurrentProjectionEnvironment joins accepted query placement with current
// recovery and complete durable processing state. Its placement policy is a purpose-specific view of shared installed
// configuration; it never consumes download authority or a download evidence DTO. The original earliest bound survives every
// blocking read, including the final repeated source checks.
type CurrentProjectionEnvironment struct {
	RootID, InstallationID string
	Policies               ContextProjectionPolicyReader
	Recovery               DownloadRecoveryReader // recovery is purpose-neutral
	Processing             ContextProjectionProcessingReader
	Now                    func() time.Time
}

var _ ContextProjectionEnvironmentReader = CurrentProjectionEnvironment{}

func (s CurrentProjectionEnvironment) ProjectionEnvironment(ctx context.Context, r ContextProjectionEvidence, actor identity.Principal) (value.ContextProjectionEnvironment, error) {
	var zero value.ContextProjectionEnvironment
	if ctx == nil || ctx.Err() != nil || s.Policies == nil || s.Recovery == nil || s.Processing == nil || s.Now == nil || !actor.Valid() || !r.Retained.Valid() || r.Retained.RootID != s.RootID || !identity.Text(r.PurposeRef, 128) || r.SourceFormat != artifact.ContextFormat || r.SourceProjectionDigest != value.ContextSourceProjectionDigest() || r.DataClass != "metadata" || r.Retained.Input.EvidenceType != "context" || r.Retained.Input.PrivacyClass != "potentialPersonalData" || r.Retained.Registration.NativeLimit != artifact.MaxContextBytes {
		return zero, value.ErrUnavailable
	}
	start := s.Now()
	until := identity.Earlier(start.Add(5*time.Second), identity.Earlier(r.ValidUntil, r.Retained.Effective.ExpiresAt))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	if !identity.Fresh(r.ObservedAt, r.ValidUntil, start, 5*time.Second) || !start.Before(until) {
		return zero, value.ErrExpired
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	// Every subsequent context derives from the preceding one. In particular a
	// late second observation cannot grant a fresh five-second interval.
	narrow := func(d time.Time) { until = identity.Earlier(until, d) }
	p, e := s.Policies.ContextProjectionPolicy(call, r.Retained.Input.Target.ClusterID, r.Retained.Registration.StoreID)
	if e != nil || !p.Valid(s.Now()) || p.RootID != s.RootID || p.InstallationID != s.InstallationID || !p.Permits(actor, r.Retained.Input.Target.ClusterID, r.Retained.Registration.StoreID, r.PurposeRef, s.Now()) {
		return zero, value.ErrUnavailable
	}
	// Own the original accepted body before any further port can reuse its
	// buffers. A changed policy with the same claimed revision must not rewrite
	// the snapshot used by the final exact comparison.
	p.PermittedRegions = append([]string{}, p.PermittedRegions...)
	p.Clients = append([]value.ContextProjectionClient{}, p.Clients...)
	for i := range p.Clients {
		p.Clients[i].Purposes = append([]string{}, p.Clients[i].Purposes...)
	}
	narrow(p.FreshUntil)
	call, c1 := context.WithDeadline(call, until)
	defer c1()
	recovery, e := s.Recovery.RecoveryState(call)
	if e != nil || !recovery.Valid(s.Now()) || recovery.InstallationID != s.InstallationID || recovery.IssuerEpoch != p.RecoveryEpoch {
		return zero, value.ErrUnavailable
	}
	narrow(recovery.FreshUntil)
	call, c2 := context.WithDeadline(call, until)
	defer c2()
	processing, e := s.Processing.ContextProjectionProcessing(call, r, recovery)
	if e != nil || !processing.Valid(s.Now()) || processing.RootID != s.RootID || processing.CaptureID != r.CaptureID || processing.Location != r.Retained.Registration.Location {
		return zero, value.ErrUnavailable
	}
	narrow(processing.ValidUntil)
	call, c3 := context.WithDeadline(call, until)
	defer c3()
	last, e := s.Policies.ContextProjectionPolicy(call, r.Retained.Input.Target.ClusterID, r.Retained.Registration.StoreID)
	if e != nil || !last.Valid(s.Now()) || last.RootID != p.RootID || last.InstallationID != p.InstallationID || last.RecoveryEpoch != p.RecoveryEpoch || last.Revision != p.Revision || last.ProtectionDigest != p.ProtectionDigest || last.Path != p.Path || !last.Permits(actor, r.Retained.Input.Target.ClusterID, r.Retained.Registration.StoreID, r.PurposeRef, s.Now()) {
		return zero, value.ErrUnavailable
	}
	// Exact policy body identity is checked, not only its claimed revision.
	a, _ := json.Marshal(struct {
		Regions []string
		Clients []value.ContextProjectionClient
	}{p.PermittedRegions, p.Clients})
	b, _ := json.Marshal(struct {
		Regions []string
		Clients []value.ContextProjectionClient
	}{last.PermittedRegions, last.Clients})
	if string(a) != string(b) {
		return zero, value.ErrUnavailable
	}
	narrow(last.FreshUntil)
	call, c4 := context.WithDeadline(call, until)
	defer c4()
	finalRecovery, e := s.Recovery.RecoveryState(call)
	if e != nil || !finalRecovery.Valid(s.Now()) || finalRecovery.InstallationID != recovery.InstallationID || finalRecovery.IssuerEpoch != recovery.IssuerEpoch || finalRecovery.Revision != recovery.Revision {
		return zero, value.ErrUnavailable
	}
	narrow(finalRecovery.FreshUntil)
	call, c5 := context.WithDeadline(call, until)
	defer c5()
	final, e := s.Processing.ContextProjectionProcessing(call, r, finalRecovery)
	if e != nil || !final.Valid(s.Now()) || final.RootID != processing.RootID || final.Epoch != processing.Epoch || final.Sequence != processing.Sequence || final.CaptureID != processing.CaptureID || final.Location != processing.Location || final.StateDigest != processing.StateDigest {
		return zero, value.ErrUnavailable
	}
	narrow(final.ValidUntil)
	body, e := json.Marshal(struct {
		Revision identity.Revision
		Guard    artifact.Digest
		Path     value.ContextProjectionPath
		Epoch    string
		Sequence int64
		State    artifact.Digest
	}{p.Revision, p.ProtectionDigest, p.Path, processing.Epoch, processing.Sequence, processing.StateDigest})
	if e != nil {
		return zero, value.ErrUnavailable
	}
	revision := p.Revision
	revision.Digest = sha256.Sum256(body)
	out := value.ContextProjectionEnvironment{RootID: s.RootID, InstallationID: s.InstallationID, Region: p.Path.AcquisitionRegion, StoreID: p.Path.StoreID, Location: r.Retained.Registration.Location, Principal: actor, PolicyRevision: revision, Recovery: recovery, Processing: processing, Path: p.Path, ObservedAt: start, ValidUntil: until}
	if call.Err() != nil || !out.Valid(s.Now()) {
		return zero, value.ErrExpired
	}
	return out, nil
}
