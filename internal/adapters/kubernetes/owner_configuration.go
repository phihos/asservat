package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const ownerConfigurationDenial = "Asservat hub owner configuration administrator is required."

type OwnerConfigurationProtection struct{ *configMapProtection }

func OwnerConfigurationAdmission(p cfg.ConfigMapAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	return configMapAdmission(p, "protected-owner-namespace", ownerConfigurationDenial)
}
func NewOwnerConfigurationProtection(observer, probe *PermissionClient, plan cfg.ConfigMapAdministration, pin GuardPin) (*OwnerConfigurationProtection, error) {
	g, err := newConfigMapProtection(observer, probe, plan, pin, "protected-owner-namespace", ownerConfigurationDenial)
	if err != nil {
		return nil, err
	}
	return &OwnerConfigurationProtection{g}, nil
}

type OwnerConfigurationSource struct {
	client                  *PermissionClient
	protection              *OwnerConfigurationProtection
	name, uid, installation string
}

var _ app.OwnerConfigurationReader = (*OwnerConfigurationSource)(nil)

func NewOwnerConfigurationSource(c *PermissionClient, p *OwnerConfigurationProtection, name, uid, installation string) (*OwnerConfigurationSource, error) {
	if c == nil || p == nil || p.configMapProtection == nil || p.observer != c || p.plan.SourceName != name || !installationRefValid(name, uid) || !authorization.UUID(uid) || !authorization.UUID(installation) {
		return nil, value.ErrInvalid
	}
	return &OwnerConfigurationSource{c, p, name, uid, installation}, nil
}
func (s *OwnerConfigurationSource) snapshot(ctx context.Context) (value.OwnerConfiguration, time.Time, error) {
	data, _, err := s.client.installationConfig(ctx, s.name, s.uid)
	if err != nil {
		return value.OwnerConfiguration{}, time.Time{}, value.ErrInvalid
	}
	return s.decodeOwnerConfiguration(data)
}

// decodeOwnerConfiguration validates only the supplied complete source value.
// It performs no I/O and does not establish an observation or native protection.
func (s *OwnerConfigurationSource) decodeOwnerConfiguration(data map[string]string) (value.OwnerConfiguration, time.Time, error) {
	var out value.OwnerConfiguration
	if len(data) != 1 || len(data["owner-pool.json"]) < 1 || len(data["owner-pool.json"]) > 64<<10 {
		return out, time.Time{}, value.ErrInvalid
	}
	b := []byte(data["owner-pool.json"])
	var wire contracts.OwnerConfiguration
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil {
		return out, time.Time{}, value.ErrInvalid
	}
	encoded, err := json.Marshal(wire)
	a, z := jsontext.Value(b), jsontext.Value(encoded)
	if err != nil || a.Canonicalize() != nil || z.Canonicalize() != nil || !bytes.Equal(a, z) || wire.Format != contracts.OwnerConfigurationFormat || wire.InstallationID != s.installation || wire.ClusterID != s.client.clusterID || wire.Namespace.Name != s.client.control.Name || wire.Namespace.UID != s.client.control.UID || wire.Revision < 1 || wire.Revision > 2147483647 {
		return out, time.Time{}, value.ErrInvalid
	}
	p := value.OwnerPool{InstallationID: wire.InstallationID, ClusterID: wire.ClusterID, IssuerEpoch: wire.IssuerEpoch, Namespace: wire.Namespace.Name, NamespaceUID: wire.Namespace.UID, Service: wire.Service.Name, ServiceUID: wire.Service.UID, Deployment: wire.Deployment.Name, DeploymentUID: wire.Deployment.UID, ServiceAccount: wire.ServiceAccount.Name, AccountUID: wire.ServiceAccount.UID, Port: wire.Port, NativePort: wire.NativePort, NativeBootstrap: wire.NativeBootstrap, NativeCandidateLimit: wire.NativeCandidateLimit, OperationPort: wire.OperationPort}
	if !p.Valid() || len(validation.IsDNS1123Label(p.Namespace)) != 0 || len(validation.IsDNS1035Label(p.Service)) != 0 || len(validation.IsDNS1123Subdomain(p.Deployment)) != 0 || len(validation.IsDNS1123Subdomain(p.ServiceAccount)) != 0 {
		return out, time.Time{}, value.ErrInvalid
	}
	_, until, err := mtls.OwnerTrustRoots(wire.IssuerRoots, s.client.now())
	if err != nil {
		return out, time.Time{}, err
	}
	return value.OwnerConfiguration{Pool: p, Revision: identity.Revision{UID: s.uid, Generation: wire.Revision, Digest: sha256.Sum256(a)}, Suspended: wire.Suspended, IssuerRoots: wire.IssuerRoots}, until, nil
}
func (s *OwnerConfigurationSource) ReadOwnerConfiguration(ctx context.Context) (value.OwnerConfigurationObservation, error) {
	var out value.OwnerConfigurationObservation
	if s == nil || ctx == nil {
		return out, value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start := s.client.now()
	protection, until, err := s.protection.current(ctx)
	if err != nil {
		return out, err
	}
	c, rootsUntil, err := s.snapshot(ctx)
	if err != nil {
		return out, err
	}
	last, lastRootsUntil, err := s.snapshot(ctx)
	if err != nil || !last.Equal(c) {
		return out, value.ErrUnavailable
	}
	if _, err = checkAdmissionGuard(ctx, s.client, s.protection.plan.Name, s.protection.pin, s.protection.policy, s.protection.binding); err != nil {
		return out, err
	}
	c.ProtectionDigest = protection
	out = value.OwnerConfigurationObservation{Configuration: c, ObservedAt: start, FreshUntil: identity.Earlier(start.Add(5*time.Second), identity.Earlier(until, identity.Earlier(rootsUntil, lastRootsUntil)))}
	if !out.Valid(s.client.now()) || ctx.Err() != nil {
		return value.OwnerConfigurationObservation{}, value.ErrUnavailable
	}
	return out, nil
}
