package bootstrap

import (
	"bytes"
	"context"
	"time"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

// newLocalClusterBootstrap composes the combined-mode connector's own
// bootstrap (mode=combined): the fleet issuance's audited pipeline with the
// installation as actor, reservations fixed to the generated local cluster
// and peer, and the record written into the Helm-rendered
// `<name>-region-bootstrap` Secret the connector mounts.
func newLocalClusterBootstrap(ctx context.Context, in *ownerInputs, pools *publicPools, issuance *fleetapp.FleetBootstrapIssuance, channel *kms.BootstrapChannel) (*fleetapp.LocalClusterBootstrap, error) {
	o, c := in.offer, in.config
	if o == nil || issuance == nil || channel == nil || c.Public == nil || c.Public.Fleet == nil {
		return nil, &fixedStepError{"local-bootstrap-inputs", mounts.ErrUnavailable}
	}
	pool, err := pools.open(ctx, "fleet-bootstrap-reserve")
	if err != nil {
		return nil, &fixedStepError{"local-bootstrap-pool", mounts.ErrUnavailable}
	}
	reserve, err := postgres.NewLocalBootstrapReservations(ctx, pool, c.InstallationID, o.offer.HubClusterID, o.peerID, ownerRandomID)
	if err != nil {
		return nil, &fixedStepError{"local-bootstrap-reserve", mounts.ErrUnavailable}
	}
	api, err := kubernetes.NewForConfig(in.kubernetes(contracts.HubAPIKubernetesTokenFile))
	if err != nil {
		return nil, &fixedStepError{"local-bootstrap-kubernetes", mounts.ErrUnavailable}
	}
	s := issuance
	issuer := fleetapp.BootstrapIssuer{Authority: fleetapp.InstallationEnrollmentAuthorizer{Settings: s.Settings, Now: s.Now}, Reservations: reserve, Credentials: s.Credentials, Records: s.Records, Audits: s.Audits, Objects: s.Objects, Activation: s.Activation, Now: s.Now}
	binding := value.PeerBinding{InstallationID: c.InstallationID, ClusterID: o.offer.HubClusterID, PeerID: o.peerID, IssuerEpoch: o.offer.IssuerEpoch, Role: value.ConnectorPeer}
	return &fleetapp.LocalClusterBootstrap{Issuer: issuer, Envelopes: channel, Binding: binding, DeliveryProfile: c.Public.Fleet.DeliveryProfile,
		Records: regionBootstrapSecret{api: api, namespace: o.namespace, name: o.bootstrapSecret}}, nil
}

// regionBootstrapSecret updates bootstrap.json of the existing Secret by
// name (Helm renders it empty and keeps it).
type regionBootstrapSecret struct {
	api             kubernetes.Interface
	namespace, name string
}

func (s regionBootstrapSecret) CheckBootstrapRecord(ctx context.Context) error {
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	_, err := s.api.CoreV1().Secrets(s.namespace).Get(call, s.name, meta.GetOptions{})
	return err
}

func (s regionBootstrapSecret) WriteBootstrapRecord(ctx context.Context, e value.BootstrapEnvelope) error {
	raw, err := kms.EncodeBootstrapRecord(e)
	defer clear(raw)
	if err != nil {
		return err
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	secrets := s.api.CoreV1().Secrets(s.namespace)
	current, err := secrets.Get(call, s.name, meta.GetOptions{})
	if err != nil {
		return err
	}
	if bytes.Equal(current.Data[contracts.ConnectorBootstrapFile], raw) {
		return nil
	}
	next := current.DeepCopy()
	if next.Data == nil {
		next.Data = map[string][]byte{}
	}
	next.Data[contracts.ConnectorBootstrapFile] = raw
	_, err = secrets.Update(call, next, meta.UpdateOptions{})
	return err
}
