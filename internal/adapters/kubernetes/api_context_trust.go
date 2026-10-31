package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"sync"
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
	mu     sync.Mutex
	cached *fleet.APIContextWorkTrust
}

// trustReuseMargin is the least remaining validity a cached trust
// observation needs to be reused. Each verification reads trust twice; each
// read is a guarded ConfigMap observation with its own proofs (native run
// 41208314967: the first work operation spent up to two seconds there and
// source work was refused at its second read).
const trustReuseMargin = 2 * time.Second

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
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.cached; c != nil && c.Valid(s.client.now().Add(trustReuseMargin)) {
		out := *c
		out.Trust.Keys = slices.Clone(c.Trust.Keys)
		return out, nil
	}
	s.cached = nil
	out, err := s.readTrust(ctx)
	if err == nil {
		c := out
		c.Trust.Keys = slices.Clone(out.Trust.Keys)
		s.cached = &c
	}
	return out, err
}

func (s *APIContextWorkTrustSource) readTrust(ctx context.Context) (fleet.APIContextWorkTrust, error) {
	var zero fleet.APIContextWorkTrust
	start := s.client.now()
	until := start.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	recovery, e := s.recovery.RecoveryState(call)
	if e != nil || !recovery.Valid(s.client.now()) || recovery.InstallationID != s.installed.InstallationID || recovery.IssuerEpoch != s.installed.IssuerEpoch {
		return zero, cfg.ErrUnavailable
	}
	until = identity.Earlier(until, recovery.FreshUntil)
	call, stopRecovery := context.WithDeadline(call, until)
	defer stopRecovery()
	guard, guardUntil, e := s.protection.current(call)
	if e != nil {
		return zero, e
	}
	until = identity.Earlier(until, guardUntil)
	call, stopGuard := context.WithDeadline(call, until)
	defer stopGuard()
	if e = s.snapshot(call); e != nil {
		return zero, e
	}
	final, finalUntil, e := s.protection.current(call)
	if e != nil || guard != final {
		return zero, cfg.ErrChanged
	}
	until = identity.Earlier(until, finalUntil)
	call, stopFinal := context.WithDeadline(call, until)
	defer stopFinal()
	if e = s.snapshot(call); e != nil {
		return zero, e
	}
	last, e := s.recovery.RecoveryState(call)
	if e != nil || !last.Valid(s.client.now()) || last.InstallationID != recovery.InstallationID || last.IssuerEpoch != recovery.IssuerEpoch || last.Revision != recovery.Revision {
		return zero, cfg.ErrChanged
	}
	until = identity.Earlier(until, last.FreshUntil)
	out, e := apiWorkTrustValue(s.installed, s.uid, start, until)
	if e != nil || call.Err() != nil || !out.Valid(s.client.now()) || !recovery.Valid(s.client.now()) || s.client.now().Before(start) {
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}
