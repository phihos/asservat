package bootstrap

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"os"
	"slices"
	"strings"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// RunInstallerClusterJoin is ADR-196's hub-side join. Run as an installation
// administrator against the hub cluster, it adds one regional cluster: it
// reads the hub's published offer and installed owner input, checks the
// region's join record against both and with the hub-api's own connector
// profile decoding, and writes the slot's guarded capability and work-trust
// sources, its retention topology and the catalog entry, then, with a path
// template, the cluster's download path (ADR-204). Every value is an
// administrator assertion checked again at runtime; a wrong entry fails
// closed at the first connection.
func RunInstallerClusterJoin(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || ctx.Err() != nil || out == nil {
		return mounts.ErrUnavailable
	}
	flags := flag.NewFlagSet("installer-cluster-join", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	kubeconfig := flags.String("kubeconfig", "", "hub Kubernetes configuration file")
	selected := flags.String("context", "", "Kubernetes context override")
	namespace := flags.String("namespace", "", "the hub's runtime namespace")
	joinFile := flags.String("join", "", "the region's regional-join.json")
	standby := flags.Int("standby", 1, "standby connections reserved for this cluster")
	captures := flags.Int("captures", 1, "concurrent captures reserved for this cluster")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *namespace == "" || *joinFile == "" || *standby < 1 || *standby > 16 || *captures < 1 || *captures > 16 {
		return mounts.ErrUnavailable
	}
	raw, err := os.ReadFile(*joinFile)
	if err != nil || len(raw) > contracts.RegionalJoinMaxBytes {
		return mounts.ErrUnavailable
	}
	join, err := contracts.DecodeRegionalJoin(strings.NewReader(string(raw)))
	if err != nil || join.Format != contracts.RegionalJoinFormat || !authorization.UUID(join.InstallationID) || !authorization.UUID(join.ClusterID) {
		return mounts.ErrUnavailable
	}
	config, _, _, err := localKubernetes(*kubeconfig, *selected, "")
	if err != nil {
		return err
	}
	offer, err := kube.ReadRegionalOffer(ctx, config, *namespace, join.InstallationID)
	if err != nil {
		return err
	}
	if executor, err := offer.RegionalExecutorOffered(); err != nil || !executor {
		return mounts.ErrUnavailable
	}
	owner, err := kube.OwnerInputs(ctx, config, *namespace, join.InstallationID)
	if err != nil {
		return err
	}
	entry, topology, err := regionalJoinEntry(offer, owner, join, *standby, *captures)
	if err != nil {
		return err
	}
	g := owner.Public.ClusterCatalog.Guard
	admins := make([]cfg.KubernetesActor, len(g.Administrators))
	for i, a := range g.Administrators {
		admins[i] = cfg.KubernetesActor{Kind: a.Kind, Name: a.Name}
	}
	control := cfg.NamespaceRef{Name: owner.Namespace.Name, UID: owner.Namespace.UID}
	// The hub retention source every regional topology names (ADR-195): the
	// exact reopened guard's digest, as the hub-worker computes it.
	plan := cfg.RetentionAdministration{Name: contracts.RetentionGuardName(join.InstallationID), ControlNamespace: control, Administrators: admins, StatusUsers: []string{contracts.RetentionStatusUser}}
	retention, err := kube.EnsureRetentionGuard(ctx, config, plan)
	if err != nil {
		return err
	}
	digest, err := kube.RetentionGuardDigest(offer.HubClusterID, plan, kube.GuardPin{PolicyUID: retention.PolicyUID, PolicyGeneration: retention.PolicyGeneration, BindingUID: retention.BindingUID, BindingResourceVersion: retention.BindingResourceVersion})
	if err != nil {
		return err
	}
	topology.Hub = contracts.RetentionPolicySource{ClusterID: offer.HubClusterID, ControlNamespaceUID: owner.Namespace.UID, ProtectionSHA256: hex.EncodeToString(digest[:])}
	downloads, err := regionalJoinDownloads(owner, entry)
	if err != nil {
		return err
	}
	joined, err := kube.JoinRegionalCluster(ctx, config, kube.ClusterJoinPlan{Control: control, Installation: join.InstallationID, Admins: admins, Catalog: owner.Public.ClusterCatalog.Source, Topology: topology, Entry: entry, Downloads: downloads})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(joined)
}

// regionalJoinDownloads is the joined cluster's derived download path
// (ADR-204 decision 4), from the owner input's path template, and the guarded
// sources it joins. The hub-api derives it for every catalog cluster. The
// capacity hub-worker derives it only for clusters with a regional capacity
// qualification, which the hub-api records from an entry's capacity section
// (ADR-197), so the processing source gains the path only with that section:
// otherwise the capacity hub-worker would never accept that source again.
// Without a template the join is unchanged.
func regionalJoinDownloads(owner contracts.OwnerDeployment, entry contracts.OwnerPublicCluster) (*kube.ClusterJoinDownloads, error) {
	e := owner.Public.DownloadEnvironment
	if e.PathTemplate == nil {
		return nil, nil
	}
	if _, err := downloadEnvironmentPaths(owner.InstallationID, owner.ClusterID, []contracts.DownloadEnvironmentPath{}, e.PathTemplate, []string{entry.ClusterID}); err != nil || !capacityRuntimeReference(e.Source) {
		return nil, mounts.ErrUnavailable
	}
	out := &kube.ClusterJoinDownloads{RootID: owner.PermissionRootID, Path: contracts.DownloadPathFor(owner.InstallationID, *e.PathTemplate, entry.ClusterID), Sources: []contracts.WorkerObjectReference{e.Source}}
	if entry.Capacity != nil {
		_, _, _, processing, _ := kube.CapacitySourceNames(owner.InstallationID)
		out.Sources = append(out.Sources, contracts.WorkerObjectReference{Name: processing})
	}
	return out, nil
}

// regionalJoinEntry checks the join record against the offer and the owner
// input and derives the catalog entry, as the hub-api will decode it.
func regionalJoinEntry(offer contracts.RegionalOffer, owner contracts.OwnerDeployment, join contracts.RegionalJoin, standby, captures int) (contracts.OwnerPublicCluster, contracts.RetentionTopologySettings, error) {
	var zero contracts.OwnerPublicCluster
	parts := strings.Split(offer.Image, "@sha256:")
	root, installation := offer.PermissionRootID, offer.InstallationID
	if len(parts) != 2 || join.InstallationID != installation || owner.InstallationID != installation || owner.PermissionRootID != root || join.IssuerEpoch != offer.IssuerEpoch || join.Executor.ImageDigest != parts[1] || offer.WorkKey == nil {
		return zero, contracts.RetentionTopologySettings{}, mounts.ErrUnavailable
	}
	projection := compiler.ProjectionDigest()
	entry := contracts.OwnerPublicCluster{ClusterID: join.ClusterID, Connector: join.Connector, Executor: join.Executor, Standby: standby, Captures: captures,
		Settings: contracts.ContextCapabilitySettings{Format: contracts.ContextCapabilityFormat, RootID: root, InstallationID: installation, ClusterID: join.ClusterID, IssuerEpoch: join.IssuerEpoch, Revision: 1, Enabled: true,
			ExecutionClass: string(artifact.ContextAPIExecution), CollectorVersion: "sha256-" + parts[1][:32], CollectorImageDigest: parts[1], ProjectionDigest: hex.EncodeToString(projection[:])},
		Trust: contracts.APIContextWorkTrustSettings{Format: contracts.APIContextTrustFormat, RootID: root, InstallationID: installation, ClusterID: join.ClusterID, IssuerEpoch: join.IssuerEpoch, Revision: 1, Enabled: true, Keys: []contracts.APIContextWorkPublicKey{*offer.WorkKey}}}
	// ADR-197: the region's capacity assertion, over the offered keys.
	if c := join.Capacity; c != nil {
		_, a := publicDigest(c.NamespaceGuardDigest)
		_, b := publicDigest(c.TemplateDigest)
		_, d := publicDigest(c.ProtectionDigest)
		if offer.Capacity == nil || !a || !b || !d || !slices.Equal(c.Keys, slices.Sorted(slices.Values(offer.Capacity.Keys))) {
			return zero, contracts.RetentionTopologySettings{}, mounts.ErrUnavailable
		}
		entry.Capacity = &contracts.OwnerPublicClusterCapacity{TemplateDigest: c.TemplateDigest, ProtectionDigest: c.ProtectionDigest, NamespaceGuardDigest: c.NamespaceGuardDigest, Keys: slices.Clone(c.Keys)}
	}
	// The hub-api's own decoding of the staged connector source.
	profile, err := publicConnectorProfile(entry, root, installation)
	if err != nil || profile.Binding.PeerID != join.PeerID || profile.Binding.ClusterID != join.ClusterID || profile.Binding.IssuerEpoch != join.IssuerEpoch {
		return zero, contracts.RetentionTopologySettings{}, mounts.ErrUnavailable
	}
	return entry, contracts.RetentionTopologySettings{SchemaVersion: "retention-topology/v1", Revision: 1, RootID: root, TargetClusterID: join.ClusterID}, nil
}
