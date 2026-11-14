package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

// OwnerSourceReader reads the Helm-rendered owner source ConfigMap
// (contracts.OwnerSource) under ordinary RBAC and completes it into the
// accepted owner configuration that hub-api, federation and connectors
// consume: the generated IDs come from the reader, the Service, Deployment and
// ServiceAccount UIDs are read by name and the issuer roots are the owner PKI
// CA from issuerRoots. UIDs and roots are read once and then reused; a replaced
// object reads as a mismatch at its consumers and needs a restart. Its
// protection digest is the deterministic source digest.
type OwnerSourceReader struct {
	client                         *PermissionClient
	digest                         artifact.Digest
	name, uid, installation, epoch string
	issuerRoots                    func(context.Context) ([][]byte, error)

	mu    sync.Mutex
	uids  map[string]string
	roots [][]byte
}

var _ app.OwnerConfigurationReader = (*OwnerSourceReader)(nil)

func NewOwnerSourceReader(c *PermissionClient, name, uid, installation, issuerEpoch string, issuerRoots func(context.Context) ([][]byte, error)) (*OwnerSourceReader, error) {
	if c == nil || issuerRoots == nil || !installationRefValid(name, uid) || !authorization.UUID(uid) || !authorization.UUID(installation) || !authorization.UUID(issuerEpoch) {
		return nil, value.ErrInvalid
	}
	return &OwnerSourceReader{client: c, digest: artifact.Digest(contracts.ConfigMapSourceDigest(c.clusterID, c.control.Name, name)), name: name, uid: uid, installation: installation, epoch: issuerEpoch, issuerRoots: issuerRoots, uids: map[string]string{}}, nil
}

// decodeOwnerSource checks the source value alone; it performs no I/O.
func decodeOwnerSource(data map[string]string) (contracts.OwnerSource, [32]byte, error) {
	var wire contracts.OwnerSource
	raw := data["owner-pool.json"]
	if len(data) != 1 || len(raw) < 1 || len(raw) > 16<<10 {
		return wire, [32]byte{}, value.ErrInvalid
	}
	b := []byte(raw)
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil {
		return contracts.OwnerSource{}, [32]byte{}, value.ErrInvalid
	}
	encoded, err := json.Marshal(wire)
	a, z := jsontext.Value(b), jsontext.Value(encoded)
	if err != nil || a.Canonicalize() != nil || z.Canonicalize() != nil || !bytes.Equal(a, z) || wire.Format != contracts.OwnerSourceFormat || wire.Revision < 1 || wire.Revision > 2147483647 ||
		len(validation.IsDNS1035Label(wire.Service)) != 0 || len(validation.IsDNS1123Subdomain(wire.Deployment)) != 0 || len(validation.IsDNS1123Subdomain(wire.ServiceAccount)) != 0 {
		return contracts.OwnerSource{}, [32]byte{}, value.ErrInvalid
	}
	return wire, sha256.Sum256(a), nil
}

// objectUID reads one object's UID by API path once and reuses it.
func (s *OwnerSourceReader) objectUID(ctx context.Context, path string) (string, error) {
	s.mu.Lock()
	uid, ok := s.uids[path]
	s.mu.Unlock()
	if ok {
		return uid, nil
	}
	uid, err := ObjectUIDFrom(ctx, s.client, path)
	if err != nil {
		return "", value.ErrUnavailable
	}
	s.mu.Lock()
	s.uids[path] = uid
	s.mu.Unlock()
	return uid, nil
}

func (s *OwnerSourceReader) ownerRoots(ctx context.Context) ([][]byte, error) {
	s.mu.Lock()
	roots := s.roots
	s.mu.Unlock()
	if roots != nil {
		return roots, nil
	}
	roots, err := s.issuerRoots(ctx)
	if err != nil || len(roots) == 0 {
		return nil, value.ErrUnavailable
	}
	s.mu.Lock()
	s.roots = roots
	s.mu.Unlock()
	return roots, nil
}

func (s *OwnerSourceReader) ReadOwnerConfiguration(ctx context.Context) (value.OwnerConfigurationObservation, error) {
	var out value.OwnerConfigurationObservation
	if s == nil || ctx == nil {
		return out, value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start := s.client.now()
	data, _, err := s.client.installationConfig(ctx, s.name, s.uid)
	if err != nil {
		return out, value.ErrInvalid
	}
	wire, digest, err := decodeOwnerSource(data)
	if err != nil {
		return out, err
	}
	ns := s.client.control
	prefix := "/api/v1/namespaces/" + ns.Name
	serviceUID, err := s.objectUID(ctx, prefix+"/services/"+wire.Service)
	if err != nil {
		return out, err
	}
	deploymentUID, err := s.objectUID(ctx, "/apis/apps/v1/namespaces/"+ns.Name+"/deployments/"+wire.Deployment)
	if err != nil {
		return out, err
	}
	accountUID, err := s.objectUID(ctx, prefix+"/serviceaccounts/"+wire.ServiceAccount)
	if err != nil {
		return out, err
	}
	roots, err := s.ownerRoots(ctx)
	if err != nil {
		return out, err
	}
	p := value.OwnerPool{InstallationID: s.installation, ClusterID: s.client.clusterID, IssuerEpoch: s.epoch, Namespace: ns.Name, NamespaceUID: ns.UID,
		Service: wire.Service, ServiceUID: serviceUID, Deployment: wire.Deployment, DeploymentUID: deploymentUID, ServiceAccount: wire.ServiceAccount, AccountUID: accountUID,
		Port: wire.Port, NativePort: wire.NativePort, NativeBootstrap: wire.NativeBootstrap, NativeCandidateLimit: wire.NativeCandidateLimit, OperationPort: wire.OperationPort}
	if !p.Valid() {
		return out, value.ErrInvalid
	}
	_, until, err := mtls.OwnerTrustRoots(roots, s.client.now())
	if err != nil {
		return out, err
	}
	c := value.OwnerConfiguration{Pool: p, Revision: identity.Revision{UID: s.uid, Generation: wire.Revision, Digest: digest}, Suspended: wire.Suspended, IssuerRoots: roots, ProtectionDigest: s.digest}
	out = value.OwnerConfigurationObservation{Configuration: c, ObservedAt: start, FreshUntil: identity.Check(start, identity.SQLFenced).Narrow(until).Until()}
	if !out.Valid(s.client.now()) || ctx.Err() != nil {
		return value.OwnerConfigurationObservation{}, value.ErrUnavailable
	}
	return out, nil
}
