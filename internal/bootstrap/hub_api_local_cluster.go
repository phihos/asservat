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
// mode=combined. It has no retention topology pin (the hub cluster's own
// in-process topology applies) and no capacity section.
func localCatalogCluster(c contracts.OwnerDeployment, o *hubAPIRegionalOffer, stored contracts.RegionalOffer) (contracts.OwnerPublicCluster, error) {
	if c.Public == nil {
		return contracts.OwnerPublicCluster{}, &fixedStepError{"local-cluster-offer", mounts.ErrUnavailable}
	}
	return catalogCluster(stored, o.offer.Image, stored.HubClusterID, o.peerID, o.namespace, o.release, c.Public.Standby, c.Public.Captures, "local-cluster")
}

// catalogCluster is one cluster's context-start entry derived from the
// stored offer and Helm-known names: the connector identity document and the
// hub's capability and work trust. A joined mode=cluster cluster is the same
// entry with its own IDs and release namespace; its retention topology is the
// in-process one of the hub retention source. image is the hub's current
// chart image: the capability names it as the collector release that plans
// the capture (provenance). The connector may run another release within the
// skew window (ADR-333); its own digests are recorded with each execution.
func catalogCluster(stored contracts.RegionalOffer, image, cluster, peerID, namespace, release string, standby, captures int, step string) (contracts.OwnerPublicCluster, error) {
	var zero contracts.OwnerPublicCluster
	if executor, err := stored.RegionalExecutorOffered(); err != nil || !executor {
		return zero, &fixedStepError{step + "-offer", mounts.ErrUnavailable}
	}
	parts := strings.Split(image, "@sha256:")
	if len(parts) != 2 || len(parts[1]) != 64 {
		return zero, &fixedStepError{step + "-image", mounts.ErrUnavailable}
	}
	image = parts[1]
	account := release + "-connector"
	deployment := contracts.ConnectorDeployment{Namespace: namespace, ServiceAccount: account, Deployment: account, ServingSlots: contracts.RegionalServingSlots, RetainedProcesses: contracts.RegionalRetainedProcesses}
	peer, err := kube.ConnectorCatalogPeer(stored, cluster, peerID, deployment)
	if err != nil {
		return zero, &fixedStepError{step + "-peer", err}
	}
	projection := compiler.ProjectionDigest()
	root, installation, epoch := stored.PermissionRootID, stored.InstallationID, stored.IssuerEpoch
	return contracts.OwnerPublicCluster{ClusterID: cluster, Connector: peer, Standby: standby, Captures: captures,
		Settings: contracts.ContextCapabilitySettings{Format: contracts.ContextCapabilityFormat, RootID: root, InstallationID: installation, ClusterID: cluster, IssuerEpoch: epoch, Revision: 1, Enabled: true,
			ExecutionClass: string(artifact.ContextAPIExecution), CollectorVersion: "sha256-" + image[:32], CollectorImageDigest: image, ProjectionDigest: hex.EncodeToString(projection[:])},
		Trust: contracts.APIContextWorkTrustSettings{Format: contracts.APIContextTrustFormat, RootID: root, InstallationID: installation, ClusterID: cluster, IssuerEpoch: epoch, Revision: 1, Enabled: true, Keys: []contracts.APIContextWorkPublicKey{*stored.WorkKey}}}, nil
}
