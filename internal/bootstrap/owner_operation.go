package bootstrap

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
	native "asservat.local/asservat/internal/transport/native"
)

// OwnerOperationConfig is the promoted owner's ADR-197 v2 operation server:
// the owner's observation pin, the one regional cluster whose standby it
// holds, and the concrete readers. The hub-worker's local claim and the
// regional standby meet on OperationPort; native and v1 serving are unchanged.
type OwnerOperationConfig struct {
	Pin      value.OwnerObservationPin
	Regional value.ConnectorObservationPin
	Owners   *postgres.OwnerEnrollments
	Proof    *kube.OwnerLocalObservationOperationReader
	Registry *postgres.ConnectorObservationOperationRegistry
}

// ownerOperationServing is composed once the server identity is active: the
// claim receiver binds the current serving leaf.
type ownerOperationServing struct {
	roots    *x509.CertPool
	serving  *mtls.OwnerBootstrapServing
	receiver *OwnerLocalObservationReceiver
	handler  *wire.HubObservationOperationHandler
	holder   *wire.HubObservationOperationHolder
}

func newOwnerOperationServing(root context.Context, c OwnerOperationConfig, server *mtls.OwnerCredentials) (*ownerOperationServing, error) {
	out := &ownerOperationServing{}
	var err error
	if out.holder, err = wire.NewHubObservationOperationHolder(root, 2, time.Now); err != nil {
		return nil, err
	}
	if out.receiver, err = NewOwnerLocalObservationReceiver(root, c.Pin, server, c.Owners, c.Proof, out.holder, 2, time.Now); err != nil {
		out.close()
		return nil, err
	}
	p := c.Regional.Profile
	ingress, err := mtls.NewOwnerObservationOperationIngress(c.Pin, server, []mtls.OwnerObservationPeer{{Binding: p.Binding, Roots: p.ClientIssuerRoots}}, time.Now)
	if err != nil {
		out.close()
		return nil, err
	}
	if out.handler, err = NewRegionalObservationOperationHandler(out.receiver.CommonAuthority(), out.holder, c.Regional, ingress, c.Registry, time.Now); err != nil {
		out.close()
		return nil, err
	}
	if out.serving, err = mtls.NewOwnerBootstrapServing(server, c.Pin.Pool); err != nil {
		out.close()
		return nil, err
	}
	if _, _, err = mtls.OwnerTrustRoots(p.ClientIssuerRoots, time.Now()); err != nil {
		out.close()
		return nil, err
	}
	out.roots = x509.NewCertPool()
	for _, der := range p.ClientIssuerRoots {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			out.close()
			return nil, value.ErrInvalid
		}
		out.roots.AddCert(cert)
	}
	return out, nil
}

func (o *ownerOperationServing) serve(root context.Context, listener net.Listener) error {
	return native.ServeOwnerObservationOperation(root, listener, o.roots, o.serving, o.receiver, o.handler, 2, 2)
}

func (o *ownerOperationServing) close() {
	if o.receiver != nil {
		o.receiver.Close()
	}
	if o.holder != nil {
		o.holder.Close()
	}
}

// ownerOperationConfig builds the v2 server's input from the guarded catalog
// (ADR-197 decisions 1 and 7). It first records the cluster's write-once
// capacity qualification. A promoted owner without a regional capacity entry
// serves none.
// ponytail: one regional capacity cluster, the first profile's one slot; a
// second needs one standby handler per cluster on the operation listener.
func (d *OwnerDeployment) ownerOperationConfig(ctx context.Context, in *ownerInputs, c contracts.OwnerDeployment, pin value.OwnerObservationPin, catalog publicCatalog, guard *kube.OwnerWorkloadProtection, owners *postgres.OwnerEnrollments) (*OwnerOperationConfig, error) {
	var regional []contracts.OwnerPublicCluster
	for _, v := range catalog.catalog.Clusters {
		if v.Capacity != nil {
			regional = append(regional, v)
		}
	}
	if len(regional) == 0 {
		return nil, nil
	}
	if len(regional) != 1 || pin.Pool.OperationPort == 0 || c.Observation == nil || c.Observation.LocalCapacity == nil || owners == nil {
		return nil, mounts.ErrUnavailable
	}
	v := regional[0]
	profile, roles, err := publicConnectorIdentity(v, c.PermissionRootID, c.InstallationID)
	if err != nil {
		return nil, err
	}
	k := v.Capacity
	template, a := publicDigest(k.TemplateDigest)
	protection, b := publicDigest(k.ProtectionDigest)
	image, e := publicDigest(v.Executor.ImageDigest)
	guardDigest, g := publicDigest(k.NamespaceGuardDigest)
	if !a || !b || !e || !g {
		return nil, mounts.ErrUnavailable
	}
	pool, err := d.public.open(ctx, "regional-capacity")
	if err != nil {
		return nil, err
	}
	qualifications, err := postgres.NewCapacityClusterQualifications(ctx, pool, c.PermissionRootID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if err = qualifications.QualifyCapacityCluster(ctx, v.ClusterID, profile.Binding.PeerID, profile.Binding.IssuerEpoch, guardDigest, k.Keys); err != nil {
		return nil, err
	}
	out := &OwnerOperationConfig{Pin: pin, Owners: owners,
		Regional: value.ConnectorObservationPin{Profile: profile, Roles: roles, TemplateDigest: template, ImageDigest: image, ProtectionDigest: protection}}
	if out.Registry, err = postgres.NewConnectorObservationOperationRegistry(d.root, pool, out.Regional); err != nil {
		return nil, mounts.ErrUnavailable
	}
	// The holder's proofs use their own client instances of the same
	// identities, each at the fixed 20 QPS: a regional observation can never
	// spend the owner identity's or the local cluster's API budget.
	control := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	observerConfig := in.kubernetes("kube-observer.token")
	observerConfig.Wrap(d.operationStats.wrap)
	observer, err := kube.NewPermissionClient(observerConfig, c.ClusterID, control, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	probe, err := kube.NewPermissionClient(in.kubernetes("kube-probe.token"), c.ClusterID, control, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	own, err := guard.WithClients(observer, probe)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if out.Proof, err = kube.NewOwnerLocalObservationOperationReader(observer, own, pin, ownerCapacityCaller(c)); err != nil {
		return nil, mounts.ErrUnavailable
	}
	return out, nil
}
