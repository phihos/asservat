package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
)

// ensure writes the offer into the kept, Helm-rendered ConfigMap when it is
// still empty and returns the stored offer: the first written offer stays,
// and the local catalog entry must name exactly the document the connector
// reads.
func (o *hubAPIRegionalOffer) ensure(ctx context.Context, api kubernetes.Interface) (contracts.RegionalOffer, error) {
	var zero contracts.RegionalOffer
	raw, err := json.Marshal(o.offer)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	if err = o.write(ctx, api, string(raw)); err != nil {
		return zero, &fixedStepError{"regional-offer-write", mounts.ErrUnavailable}
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	current, err := api.CoreV1().ConfigMaps(o.namespace).Get(call, o.name, meta.GetOptions{})
	if err != nil {
		return zero, &fixedStepError{"regional-offer-read", mounts.ErrUnavailable}
	}
	var stored contracts.RegionalOffer
	d := json.NewDecoder(bytes.NewReader([]byte(current.Data[contracts.RegionalOfferFile])))
	d.DisallowUnknownFields()
	if d.Decode(&stored) != nil || stored.InstallationID != o.offer.InstallationID || stored.HubClusterID != o.offer.HubClusterID {
		return zero, &fixedStepError{"regional-offer-stored", mounts.ErrUnavailable}
	}
	return stored, nil
}

// localCatalogCluster is the hub's own cluster as a context-start target in
// mode=combined (the entry a regional join added for a remote cluster): the
// local connector's identity document derived from the stored offer, the
// executor pin it presents (its namespace and account UIDs and the startup
// digest over Helm-known values) and the hub's own capability and work trust.
// It has no retention topology (the hub cluster's own retention applies) and
// no capacity section.
func localCatalogCluster(ctx context.Context, api kubernetes.Interface, c contracts.OwnerDeployment, o *hubAPIRegionalOffer, stored contracts.RegionalOffer) (contracts.OwnerPublicCluster, error) {
	var zero contracts.OwnerPublicCluster
	if executor, err := stored.RegionalExecutorOffered(); err != nil || !executor || c.Public == nil {
		return zero, &fixedStepError{"local-cluster-offer", mounts.ErrUnavailable}
	}
	parts := strings.Split(stored.Image, "@sha256:")
	if len(parts) != 2 || len(parts[1]) != 64 {
		return zero, &fixedStepError{"local-cluster-image", mounts.ErrUnavailable}
	}
	image := parts[1]
	cluster, account, capacity := stored.HubClusterID, o.release+"-connector", o.release+"-connector-capacity"
	deployment := contracts.ConnectorDeployment{Namespace: o.namespace, ServiceAccount: account, Deployment: account, ServingSlots: contracts.RegionalServingSlots, RetainedProcesses: contracts.RegionalRetainedProcesses}
	peer, err := kube.ConnectorCatalogPeer(stored, cluster, o.peerID, deployment)
	if err != nil {
		return zero, &fixedStepError{"local-cluster-peer", err}
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	sa, err := api.CoreV1().ServiceAccounts(o.namespace).Get(call, account, meta.GetOptions{})
	if err != nil {
		return zero, &fixedStepError{"local-cluster-account", mounts.ErrUnavailable}
	}
	projection := compiler.ProjectionDigest()
	settings := contracts.ConnectorAPIContextSettings{RootID: stored.PermissionRootID, InstallationID: stored.InstallationID, ClusterID: cluster, IssuerEpoch: stored.IssuerEpoch,
		Namespace: o.namespace, Account: account, Deployment: account, CapacityAccount: capacity, ImageDigest: image, ProjectionDigest: hex.EncodeToString(projection[:])}
	startup := kube.ConnectorAPIStartupDigest(settings)
	root, installation, epoch := stored.PermissionRootID, stored.InstallationID, stored.IssuerEpoch
	return contracts.OwnerPublicCluster{ClusterID: cluster, Connector: peer, Standby: c.Public.Standby, Captures: c.Public.Captures,
		Executor: contracts.OwnerPublicExecutor{NamespaceUID: c.Namespace.UID, AccountUID: string(sa.UID), StartupDigest: hex.EncodeToString(startup[:]), ImageDigest: image},
		Settings: contracts.ContextCapabilitySettings{Format: contracts.ContextCapabilityFormat, RootID: root, InstallationID: installation, ClusterID: cluster, IssuerEpoch: epoch, Revision: 1, Enabled: true,
			ExecutionClass: string(artifact.ContextAPIExecution), CollectorVersion: "sha256-" + image[:32], CollectorImageDigest: image, ProjectionDigest: hex.EncodeToString(projection[:])},
		Trust: contracts.APIContextWorkTrustSettings{Format: contracts.APIContextTrustFormat, RootID: root, InstallationID: installation, ClusterID: cluster, IssuerEpoch: epoch, Revision: 1, Enabled: true, Keys: []contracts.APIContextWorkPublicKey{*stored.WorkKey}}}, nil
}
