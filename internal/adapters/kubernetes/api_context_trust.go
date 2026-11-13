package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
)

const apiContextTrustDenial = "Asservat API context work trust administrator is required."

type APIContextWorkTrustProtection struct{ *configMapProtection }

func APIContextWorkTrustAdmission(p cfg.ConfigMapAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	return configMapAdmission(p, "protected-api-context-work-trust", apiContextTrustDenial)
}
func NewAPIContextWorkTrustProtection(observer, probe *PermissionClient, p cfg.ConfigMapAdministration, pin GuardPin) (*APIContextWorkTrustProtection, error) {
	guard, e := newConfigMapProtection(observer, probe, p, pin, "protected-api-context-work-trust", apiContextTrustDenial)
	if e != nil {
		return nil, e
	}
	return &APIContextWorkTrustProtection{guard}, nil
}

// APIContextWorkTrustSource fixes the accepted first-profile public keys by
// value. The separate installer supplies their provenance and sign-only hub
// credential. Source equality/current native denial are not key issuance.
type APIContextWorkTrustSource struct {
	client     *PermissionClient
	protection *APIContextWorkTrustProtection
	recovery   app.RecoveryReader
	name, uid  string
	installed  contracts.APIContextWorkTrustSettings
	canonical  []byte

	// mu serializes reads so concurrent verifiers share one; cached is the
	// last observation, reused only while trustReuseMargin of its own
	// original interval remains.
	mu     ctxMutex
	cached *fleet.APIContextWorkTrust
}

// trustReuseMargin is the least remaining validity a cached trust
// observation needs to be reused. Each verification reads trust twice; each
// read is a guarded ConfigMap observation with its own proofs (native run
// 41208314967: the first work operation spent up to two seconds there and
// source work was refused at its second read).
// Three seconds, like the owner route: a start's receiver/recovery bound is
// the earliest reused observation, and with two seconds a start could begin
// with under one second left for preparation headroom (installed incident
// runs 41301126897, 41299848255, 41284876053).
const trustReuseMargin = 3 * time.Second

var _ app.APIContextWorkTrustReader = (*APIContextWorkTrustSource)(nil)

func apiWorkTrustValue(p contracts.APIContextWorkTrustSettings, uid string, now, until time.Time) (fleet.APIContextWorkTrust, error) {
	if p.Format != contracts.APIContextTrustFormat || !p.Enabled || !authorization.UUID(p.RootID) || !authorization.UUID(p.InstallationID) || !authorization.UUID(p.ClusterID) || !authorization.UUID(p.IssuerEpoch) || !authorization.UUID(uid) || p.Revision < 1 || p.Revision > 2147483647 || len(p.Keys) < 1 || len(p.Keys) > 8 {
		return fleet.APIContextWorkTrust{}, cfg.ErrInvalid
	}
	encoded, e := contracts.EncodeAPIContextTrust(p)
	if e != nil {
		return fleet.APIContextWorkTrust{}, cfg.ErrInvalid
	}
	out := fleet.APIContextWorkTrust{RootID: p.RootID, InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, Trust: fleet.WorkTrust{Revision: identity.Revision{UID: uid, Generation: p.Revision, Digest: sha256.Sum256(encoded)}, ObservedAt: now, FreshUntil: until}}
	for _, k := range p.Keys {
		key, e := base64.RawURLEncoding.Strict().DecodeString(k.PublicKey)
		if e != nil || len(key) != 32 || base64.RawURLEncoding.EncodeToString(key) != k.PublicKey {
			return fleet.APIContextWorkTrust{}, cfg.ErrInvalid
		}
		before, e1 := time.Parse(time.RFC3339Nano, k.NotBefore)
		after, e2 := time.Parse(time.RFC3339Nano, k.NotAfter)
		if e1 != nil || e2 != nil || before.UTC().Format(time.RFC3339Nano) != k.NotBefore || after.UTC().Format(time.RFC3339Nano) != k.NotAfter {
			return fleet.APIContextWorkTrust{}, cfg.ErrInvalid
		}
		out.Trust.Keys = append(out.Trust.Keys, fleet.WorkKey{ID: k.ID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PublicKey: key, NotBefore: before, NotAfter: after})
	}
	if !out.Valid(now) {
		return fleet.APIContextWorkTrust{}, cfg.ErrInvalid
	}
	return out, nil
}

// The reader's cluster holds the guarded source; installed.ClusterID names the
// cluster whose works it verifies. The hub holds every workload cluster's
// trust in its control namespace (ADR-180); a region pins its own cluster in
// its deployment validation.
func NewAPIContextWorkTrustSource(c *PermissionClient, p *APIContextWorkTrustProtection, recovery app.RecoveryReader, name, uid string, installed contracts.APIContextWorkTrustSettings) (*APIContextWorkTrustSource, error) {
	if c == nil || p == nil || p.configMapProtection == nil || p.observer != c || p.plan.SourceName != name || recovery == nil || !installationRefValid(name, uid) {
		return nil, cfg.ErrInvalid
	}
	n := c.now()
	if _, e := apiWorkTrustValue(installed, uid, n, n.Add(5*time.Second)); e != nil {
		return nil, e
	}
	canonical, e := contracts.EncodeAPIContextTrust(installed)
	if e != nil {
		return nil, e
	}
	installed.Keys = slices.Clone(installed.Keys)
	return &APIContextWorkTrustSource{client: c, protection: p, recovery: recovery, name: name, uid: uid, installed: installed, canonical: canonical}, nil
}
func (s *APIContextWorkTrustSource) snapshot(ctx context.Context) error {
	data, ref, e := s.client.installationConfigMode(ctx, s.name, s.uid, true)
	if e != nil || len(data) != 1 || ref.UID != s.uid {
		return cfg.ErrUnavailable
	}
	p, e := contracts.DecodeAPIContextTrust([]byte(data["api-context-work-trust.json"]))
	if e != nil {
		return cfg.ErrChanged
	}
	b, e := contracts.EncodeAPIContextTrust(p)
	if e != nil || !bytes.Equal(b, s.canonical) {
		return cfg.ErrChanged
	}
	return nil
}
func (s *APIContextWorkTrustSource) APIContextWorkTrust(ctx context.Context) (fleet.APIContextWorkTrust, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return fleet.APIContextWorkTrust{}, cfg.ErrInvalid
	}
	if !s.mu.lock(ctx) {
		return fleet.APIContextWorkTrust{}, cfg.ErrUnavailable
	}
	defer s.mu.unlock()
	if c := s.cached; c != nil && c.Valid(s.client.now().Add(trustReuseMargin)) {
		out := *c
		out.Trust.Keys = slices.Clone(c.Trust.Keys)
		return out, nil
	}
	previous := s.cached
	s.cached = nil
	out, err := s.readTrust(ctx)
	if err == nil {
		c := out
		c.Trust.Keys = slices.Clone(out.Trust.Keys)
		s.cached = &c
		return out, nil
	}
	// A failed refresh does not void an observation still inside its own
	// original interval: one transient guard read otherwise denied every
	// work verification until the next success (native run 41246065147
	// refused a Save's collect work at "trust"). Nothing is extended.
	// A known change, or any recovery refusal, never falls back to the earlier
	// observation; only guard/snapshot read failures do.
	var step trustStep
	recoveryStep := errors.As(err, &step) && strings.HasPrefix(step.step, "recovery")
	if previous != nil && !recoveryStep && !errors.Is(err, cfg.ErrChanged) && previous.Valid(s.client.now()) && ctx.Err() == nil {
		s.cached = previous
		kept := *previous
		kept.Trust.Keys = slices.Clone(previous.Trust.Keys)
		return kept, nil
	}
	return out, err
}

func (s *APIContextWorkTrustSource) readTrust(ctx context.Context) (fleet.APIContextWorkTrust, error) {
	var zero fleet.APIContextWorkTrust
	start := s.client.now()
	// until bounds this check's reads (five seconds); valid is the ADR-311
	// interval the completed trust check may be used for, never past recovery.
	until := start.Add(5 * time.Second)
	valid := start.Add(identity.AuthorityRecheckInterval)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	recovery, e := s.recovery.RecoveryState(call)
	if e != nil || !recovery.Valid(s.client.now()) || recovery.InstallationID != s.installed.InstallationID || recovery.IssuerEpoch != s.installed.IssuerEpoch {
		return zero, trustStep{"recovery", cfg.ErrUnavailable}
	}
	until = identity.Earlier(until, recovery.FreshUntil)
	valid = identity.Earlier(valid, recovery.FreshUntil)
	call, stopRecovery := context.WithDeadline(call, until)
	defer stopRecovery()
	if e = s.snapshot(call); e != nil {
		return zero, trustStep{"snapshot", e}
	}
	last, e := s.recovery.RecoveryState(call)
	if e != nil || !last.Valid(s.client.now()) || last.InstallationID != recovery.InstallationID || last.IssuerEpoch != recovery.IssuerEpoch || last.Revision != recovery.Revision {
		return zero, trustStep{"recovery-final", cfg.ErrChanged}
	}
	valid = identity.Earlier(valid, last.FreshUntil)
	out, e := apiWorkTrustValue(s.installed, s.uid, start, valid)
	if e != nil || call.Err() != nil || !out.Valid(s.client.now()) || !recovery.Valid(s.client.now()) || s.client.now().Before(start) {
		return zero, trustStep{"value", cfg.ErrUnavailable}
	}
	return out, nil
}

// trustStep names where a work-trust read stopped (diagnostic only).
type trustStep struct {
	step string
	err  error
}

func (e trustStep) Error() string     { return "work trust " + e.step }
func (e trustStep) Unwrap() error     { return e.err }
func (e trustStep) FixedStep() string { return "trust-" + e.step }
