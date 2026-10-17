package kubernetes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	fleet "asservat.local/asservat/internal/domain/fleet"
)

// These values are already independently selected by the original installation
// and concrete retained bridge. A later projection input cannot choose another
// provider, omit a guard exception, or replace the original native guard pins.
// The separate PKI recipe producer owns its purpose-specific role names/tokens.
func ownerIdentityProjectionInputBound(root *OwnerIdentityRoleRoot, in contracts.OwnerDeployment, now time.Time) bool {
	if root == nil || root.resources == nil || root.bridge == nil || root.bridge.source == nil || root.bridge.source.protection == nil || in.Observation == nil || !ownerPromotionAdmitted(root.input.OwnerLayout, in, now) || in.Format != contracts.OwnerDeploymentFormat || !authorization.UUID(in.PermissionRootID) || in.Connections < 1 || in.Connections > 64 || in.Concurrency < 1 || in.Concurrency > 16 || in.Concurrency > in.Connections || in.Postgres.MaxConnections != 1 || providerconfig.ValidateOwner(in.Kubernetes, in.Postgres, in.AuditStore, in.KeyService, now) != nil {
		return false
	}
	if !ownerProviderProjectionSelectionBound(root, in, now) {
		return false
	}
	original := root.resources.initial
	if in.InstallationID != original.InstallationID || in.ClusterID != original.ClusterID || in.Namespace != original.Namespace || in.ConfigurationUID != root.input.OwnerConfigurationUID || !equalJSON(in.Kubernetes, original.Kubernetes) || !equalJSON(in.AuditStore, original.AuditStore) {
		return false
	}
	pg := original.Postgres
	pg.MaxConnections = 1 // Each fixed private role has its own single connection.
	auditKey := contracts.ConfigurationKeyService{Endpoint: in.KeyService.Endpoint, Roots: in.KeyService.Roots, AuditMount: in.KeyService.AuditMount, AuditKey: in.KeyService.AuditKey}
	if !equalJSON(in.Postgres, pg) || !equalJSON(auditKey, original.KeyService) {
		return false
	}
	plan := root.bridge.administration.Owner
	guard := root.bridge.source.protection
	if !equalJSON(plan, guard.plan) || plan.Deployment != root.input.Deployment.Name || plan.DeploymentUID != root.input.Deployment.UID || plan.ControlNamespace != (cfg.NamespaceRef{Name: in.Namespace.Name, UID: in.Namespace.UID}) {
		return false
	}
	want := contracts.OwnerDeploymentGuard{Name: plan.Name, PolicyUID: guard.pin.PolicyUID, PolicyGeneration: guard.pin.PolicyGeneration, BindingUID: guard.pin.BindingUID, BindingResourceVersion: guard.pin.BindingResourceVersion}
	for _, a := range plan.Administrators {
		want.Administrators = append(want.Administrators, contracts.OwnerDeploymentActor{Kind: string(a.Kind), Name: a.Name})
	}
	if !equalJSON(in.WorkloadGuard, want) || in.ConfigurationProbes == nil || len(in.ConfigurationProbes) != len(plan.ConfigurationProbes) || in.SchedulingLeases == nil || len(in.SchedulingLeases) != len(plan.SchedulingLeases) {
		return false
	}
	for i, p := range plan.ConfigurationProbes {
		if in.ConfigurationProbes[i] != (contracts.OwnerConfigurationProbe{ConfigMap: p.ConfigMap, ServiceAccount: p.ServiceAccount}) {
			return false
		}
	}
	for i, p := range plan.SchedulingLeases {
		if in.SchedulingLeases[i] != (contracts.OwnerSchedulingLease{Lease: p.Lease, ServiceAccount: p.ServiceAccount}) {
			return false
		}
	}
	var history *contracts.OwnerInitialHistoryProbe
	if p := plan.InitialHistoryProbe; p != nil {
		history = &contracts.OwnerInitialHistoryProbe{Namespace: contracts.WorkerObjectReference{Name: p.Namespace.Name, UID: p.Namespace.UID}, ServiceAccount: contracts.WorkerObjectReference{Name: p.ServiceAccount, UID: p.ServiceAccountUID}, Configuration: p.Configuration}
	}
	if !equalJSON(in.InitialHistoryProbe, history) {
		return false
	}
	var starts *contracts.OwnerDeploymentAPIContextStarts
	if p := plan.APIContextStarts; p != nil {
		starts = &contracts.OwnerDeploymentAPIContextStarts{CapacityAccount: contracts.WorkerObjectReference{Name: p.CapacityAccount, UID: p.CapacityAccountUID}, ExecutionAccount: contracts.WorkerObjectReference{Name: p.ExecutionAccount, UID: p.ExecutionAccountUID}}
	}
	if !equalJSON(in.APIContextStarts, starts) {
		return false
	}
	var capacity *contracts.OwnerDeploymentCapacityProbe
	if p := plan.CapacityProbe; p != nil {
		capacity = &contracts.OwnerDeploymentCapacityProbe{ServiceAccount: contracts.WorkerObjectReference{Name: p.ServiceAccount, UID: p.ServiceAccountUID}}
	}
	if !equalJSON(in.CapacityProbe, capacity) {
		return false
	}
	o := in.Observation
	if o.Format != originalOwnerObservationFormat(root.resources.observationFormat) || !ownerIdentityDigestValid(o.TemplateDigest) || !ownerIdentityDigestValid(o.ImageDigest) || o.ProtectionDigest != hex.EncodeToString(guard.digest[:]) || len(o.Peers) < 1 || len(o.Peers) > 16 {
		return false
	}
	seen := map[fleet.PeerBinding]bool{}
	for _, p := range o.Peers {
		b := fleet.PeerBinding{InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PeerID: p.PeerID, Role: fleet.ConnectorPeer}
		if !b.Valid() || seen[b] || p.InstallationID != original.InstallationID || p.IssuerEpoch != original.IssuerEpoch {
			return false
		}
		if _, _, e := mtls.OwnerTrustRoots(p.Roots, now); e != nil {
			return false
		}
		seen[b] = true
	}
	return true
}

// This is an original-object read under the caller's already bounded proof, not
// a new observation allowance. Full current native/source checks remain before
// each later claim/CAS/CREATE. API-defaulted template fields are all retained.
func (s *OwnerIdentityProjection) originalInput(ctx context.Context, snapshot contracts.InitialRuntimeResourceSnapshot) error {
	if !ownerIdentityProjectionInputBound(s.root, s.input, s.root.resources.now()) || len(snapshot.State.Objects) != contracts.InitialRuntimeResourceCount || snapshot.State.Objects[17].Receipt == nil || snapshot.State.Objects[18].Receipt == nil {
		return cfg.ErrChanged
	}
	policy, binding := snapshot.State.Objects[17].Receipt, snapshot.State.Objects[18].Receipt
	g := s.input.WorkloadGuard
	if policy.UID != g.PolicyUID || policy.Generation != g.PolicyGeneration || binding.UID != g.BindingUID || binding.ResourceVersion != g.BindingResourceVersion || !s.root.resources.now().Before(snapshot.ValidUntil) {
		return cfg.ErrChanged
	}
	call, end := context.WithDeadline(ctx, snapshot.ValidUntil)
	defer end()
	d, e := s.readLaunchDeployment(call)
	if e != nil {
		return e
	}
	original := d.DeepCopy()
	if snapshot.State.OwnerLaunch != nil && d.Spec.Replicas != nil && *d.Spec.Replicas == 1 {
		if !ownerIdentityClaimedLaunchObject(d, snapshot.State, s.root.input) {
			return cfg.ErrChanged
		}
		*original.Spec.Replicas = 0
		original.Generation = 1
		delete(original.Annotations, ownerIdentityLaunchMarker)
	} else if snapshot.State.OwnerLaunch != nil && snapshot.State.OwnerLaunch.Receipt != nil {
		return cfg.ErrChanged
	}
	raw, e := json.Marshal(original)
	if e != nil {
		return cfg.ErrChanged
	}
	if _, e = s.root.resources.verified(call, raw, snapshot.State, 10); e != nil {
		return e
	}
	digest, e := ConnectorAPITemplateDigest(d.Spec.Template)
	if e != nil || hex.EncodeToString(digest[:]) != s.input.Observation.TemplateDigest || len(d.Spec.Template.Spec.Containers) != 1 || !strings.HasSuffix(d.Spec.Template.Spec.Containers[0].Image, "@sha256:"+s.input.Observation.ImageDigest) {
		return cfg.ErrChanged
	}
	if s.root.input.OwnerLayout == contracts.OwnerProviderInstalledLayout {
		if e = s.originalBootstrapSelection(call, snapshot, snapshot.ValidUntil); e != nil {
			return e
		}
	}
	return initialHandoverDeadline(call, s.root.resources.now, snapshot.ValidUntil)
}
