package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/util/validation"
)

func connectorAPIDigest(s string) (artifact.Digest, error) {
	var d artifact.Digest
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != s {
		return d, cfg.ErrInvalid
	}
	copy(d[:], b)
	if d == (artifact.Digest{}) {
		return d, cfg.ErrInvalid
	}
	return d, nil
}

// ConnectorAPISettings derives the executor's startup facts from the
// connector's own workload (UIDs read by name at start) and the image digest of its Helm values. Template, input and guard pins of
// the former installer are gone; Kubernetes RBAC protects the objects.
func ConnectorAPISettings(rootID string, binding fleet.PeerBinding, workload ConnectorWorkload, imageDigest string) (contracts.ConnectorAPIContextSettings, error) {
	projection := compiler.ProjectionDigest()
	s := contracts.ConnectorAPIContextSettings{Format: contracts.ConnectorAPIContextFormat, RootID: rootID, InstallationID: binding.InstallationID, ClusterID: binding.ClusterID, IssuerEpoch: binding.IssuerEpoch,
		Namespace: workload.Namespace, NamespaceUID: workload.NamespaceUID, Account: workload.Account, AccountUID: workload.AccountUID, Deployment: workload.Deployment, DeploymentUID: workload.DeploymentUID,
		ImageDigest: imageDigest, ProjectionDigest: hex.EncodeToString(projection[:]), WorkloadProtectionDigest: hex.EncodeToString(workload.Digest[:])}
	if !connectorAPISettingsValid(s) {
		return contracts.ConnectorAPIContextSettings{}, cfg.ErrInvalid
	}
	return s, nil
}

func connectorAPISettingsValid(p contracts.ConnectorAPIContextSettings) bool {
	if p.Format != contracts.ConnectorAPIContextFormat || len(p.Inputs) != 0 || p.StartGuard != (contracts.ConnectorAPIStartGuard{}) || p.TemplateDigest != "" || p.ConnectorRevision != (contracts.APIContextRevision{}) {
		return false
	}
	for _, id := range []string{p.RootID, p.InstallationID, p.ClusterID, p.IssuerEpoch, p.NamespaceUID, p.AccountUID, p.DeploymentUID} {
		if !authorization.UUID(id) {
			return false
		}
	}
	for _, name := range []string{p.Account, p.Deployment} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return false
		}
	}
	if len(validation.IsDNS1123Label(p.Namespace)) != 0 {
		return false
	}
	for _, s := range []string{p.ImageDigest, p.ProjectionDigest, p.WorkloadProtectionDigest} {
		if _, e := connectorAPIDigest(s); e != nil {
			return false
		}
	}
	projection, e := connectorAPIDigest(p.ProjectionDigest)
	return e == nil && projection == compiler.ProjectionDigest()
}

// ConnectorAPIProcess is the executor's identity: the startup facts of its
// Helm-rendered workload and a process epoch chosen at start. Kubernetes RBAC
// protects the workload; the process does not attest itself (ADR-330 D3).
type ConnectorAPIProcess struct {
	binding value.APIProcessBinding
	now     func() time.Time
}

func NewConnectorAPIProcess(s contracts.ConnectorAPIContextSettings, podUID string, now func() time.Time) (*ConnectorAPIProcess, error) {
	if !connectorAPISettingsValid(s) || !authorization.UUID(podUID) || now == nil {
		return nil, cfg.ErrInvalid
	}
	image, _ := connectorAPIDigest(s.ImageDigest)
	b := value.APIProcessBinding{InstallationID: s.InstallationID, ClusterID: s.ClusterID, IssuerEpoch: s.IssuerEpoch, NamespaceUID: s.NamespaceUID, AccountUID: s.AccountUID, PodUID: podUID, ProcessEpoch: uuid.NewString(), StartupDigest: ConnectorAPIStartupDigest(s), ImageDigest: image}
	return &ConnectorAPIProcess{binding: b, now: now}, nil
}

func (p *ConnectorAPIProcess) ProcessEpoch() string { return p.binding.ProcessEpoch }

func (p *ConnectorAPIProcess) ReadAPIProcess(ctx context.Context) (value.APIProcessObservation, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return value.APIProcessObservation{}, cfg.ErrUnavailable
	}
	now := p.now()
	return value.APIProcessObservation{Binding: p.binding, CheckedAt: now, ValidUntil: now.Add(identity.AuthorityRecheckInterval)}, nil
}

// ConnectorAPIStartupDigest is the executor's startup pin, which the hub's
// catalog entry names. It binds only values both sides know from Helm: the
// cluster binding, the workload names and the image.
func ConnectorAPIStartupDigest(s contracts.ConnectorAPIContextSettings) artifact.Digest {
	bound, _ := json.Marshal(struct {
		Format, RootID, InstallationID, ClusterID, IssuerEpoch string
		Namespace, Account, Deployment                         string
		ImageDigest, ProjectionDigest                          string
	}{"asservat-connector-api-startup/v3", s.RootID, s.InstallationID, s.ClusterID, s.IssuerEpoch, s.Namespace, s.Account, s.Deployment, s.ImageDigest, s.ProjectionDigest})
	return sha256.Sum256(bound)
}
