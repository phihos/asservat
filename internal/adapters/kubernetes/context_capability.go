package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"time"

	captureapp "asservat.local/asservat/internal/application/capture"
	executionapp "asservat.local/asservat/internal/application/execution"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	admission "k8s.io/api/admissionregistration/v1"
)

const contextCapabilityDenial = "Asservat context capability administrator is required."

type ContextCapabilityProtection struct{ *configMapProtection }

func ContextCapabilityAdmission(p cfg.ConfigMapAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	return configMapAdmission(p, "protected-context-capability", contextCapabilityDenial)
}
func NewContextCapabilityProtection(observer, probe *PermissionClient, p cfg.ConfigMapAdministration, pin GuardPin) (*ContextCapabilityProtection, error) {
	g, err := newConfigMapProtection(observer, probe, p, pin, "protected-context-capability", contextCapabilityDenial)
	if err != nil {
		return nil, err
	}
	return &ContextCapabilityProtection{g}, nil
}

// The independently installed profile is copied by value. A mutable observed
// ConfigMap cannot qualify another image, projection, cluster or epoch. Runtime
// recovery and native admission must remain current on every read.
type ContextCapabilitySource struct {
	client     *PermissionClient
	protection *ContextCapabilityProtection
	recovery   fleetapp.RecoveryReader
	name, uid  string
	installed  contracts.ContextCapabilitySettings
}

var _ captureapp.ContextCapabilityReader = (*ContextCapabilitySource)(nil)
var _ executionapp.APIContextCapability = (*ContextCapabilitySource)(nil)

func capabilityDigest(s string) (artifact.Digest, bool) {
	var d artifact.Digest
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(d) || hex.EncodeToString(b) != s {
		return d, false
	}
	copy(d[:], b)
	return d, d != (artifact.Digest{})
}

func validInstalledCapability(p contracts.ContextCapabilitySettings) bool {
	image, ok := capabilityDigest(p.CollectorImageDigest)
	projection, projectionOK := capabilityDigest(p.ProjectionDigest)
	return p.Format == contracts.ContextCapabilityFormat && authorization.UUID(p.RootID) && authorization.UUID(p.InstallationID) && authorization.UUID(p.ClusterID) && authorization.UUID(p.IssuerEpoch) && p.Revision > 0 && p.Revision <= 2147483647 && p.ExecutionClass == string(artifact.ContextAPIExecution) && identity.Text(p.CollectorVersion, 64) && ok && image != (artifact.Digest{}) && projectionOK && projection == compiler.ProjectionDigest()
}

// The reader's cluster holds the guarded source; installed.ClusterID names the
// target cluster it qualifies. The first installed profile keeps every
// workload cluster's capability in the hub's control namespace (ADR-179).
func NewContextCapabilitySource(c *PermissionClient, p *ContextCapabilityProtection, recovery fleetapp.RecoveryReader, name, uid string, installed contracts.ContextCapabilitySettings) (*ContextCapabilitySource, error) {
	if c == nil || p == nil || p.configMapProtection == nil || p.observer != c || p.plan.SourceName != name || recovery == nil || !installationRefValid(name, uid) || !authorization.UUID(uid) || !validInstalledCapability(installed) {
		return nil, planning.ErrInvalid
	}
	return &ContextCapabilitySource{c, p, recovery, name, uid, installed}, nil
}

func (s *ContextCapabilitySource) snapshot(ctx context.Context) (planning.ContextCapability, error) {
	var out planning.ContextCapability
	data, ref, err := s.client.installationConfigMode(ctx, s.name, s.uid, true)
	if err != nil || len(data) != 1 || len(data["context-capability.json"]) == 0 || len(data["context-capability.json"]) > contracts.ContextCapabilityMaxBytes {
		return out, cfg.ErrUnavailable
	}
	raw := []byte(data["context-capability.json"])
	var w contracts.ContextCapabilitySettings
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&w) != nil {
		return out, cfg.ErrInvalid
	}
	b, err := json.Marshal(w)
	a, z := jsontext.Value(raw), jsontext.Value(b)
	if err != nil || a.Canonicalize() != nil || z.Canonicalize() != nil || !bytes.Equal(a, z) || w != s.installed || !w.Enabled {
		return out, cfg.ErrChanged
	}
	image, _ := capabilityDigest(w.CollectorImageDigest)
	projection, _ := capabilityDigest(w.ProjectionDigest)
	out = planning.ContextCapability{ExecutionClass: artifact.ContextAPIExecution, Revision: identity.Revision{UID: ref.UID, Generation: w.Revision, Digest: sha256.Sum256(a)}, Enabled: true, CollectorVersion: w.CollectorVersion, CollectorImageDigest: image, ProjectionDigest: projection}
	return out, nil
}

func (s *ContextCapabilitySource) ContextCapability(ctx context.Context, target authorization.Target) (planning.ContextCapability, error) {
	var zero planning.ContextCapability
	if s == nil || ctx == nil || ctx.Err() != nil || !target.Valid() || target.ClusterID != s.installed.ClusterID {
		return zero, cfg.ErrInvalid
	}
	started := s.client.now()
	until := started.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	r, err := s.recovery.RecoveryState(call)
	if err != nil || !r.Valid(s.client.now()) || r.InstallationID != s.installed.InstallationID || r.IssuerEpoch != s.installed.IssuerEpoch {
		return zero, cfg.ErrUnavailable
	}
	until = identity.Earlier(until, r.FreshUntil)
	call, stopRecovery := context.WithDeadline(call, until)
	defer stopRecovery()
	guard, guardUntil, err := s.protection.current(call)
	if err != nil {
		return zero, err
	}
	until = identity.Earlier(until, guardUntil)
	call, stopGuard := context.WithDeadline(call, until)
	defer stopGuard()
	out, err := s.snapshot(call)
	if err != nil {
		return zero, err
	}
	last, lastUntil, err := s.protection.current(call)
	if err != nil || last != guard {
		return zero, cfg.ErrChanged
	}
	until = identity.Earlier(until, lastUntil)
	call, stopFinal := context.WithDeadline(call, until)
	defer stopFinal()
	again, err := s.snapshot(call)
	if err != nil || out != again {
		return zero, cfg.ErrChanged
	}
	lastRecovery, err := s.recovery.RecoveryState(call)
	if err != nil || !lastRecovery.Valid(s.client.now()) || lastRecovery.InstallationID != r.InstallationID || lastRecovery.IssuerEpoch != r.IssuerEpoch || lastRecovery.Revision != r.Revision {
		return zero, cfg.ErrChanged
	}
	until = identity.Earlier(until, lastRecovery.FreshUntil)
	out.ObservedAt, out.FreshUntil = started, until
	if call.Err() != nil || !out.Valid(s.client.now()) || !r.Valid(s.client.now()) || s.client.now().Before(started) {
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}
