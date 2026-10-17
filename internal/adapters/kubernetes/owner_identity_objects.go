package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

func ownerIdentityAnnotations(a contracts.OwnerIdentityActivation, p *contracts.OwnerIdentityProjectionClaim) map[string]string {
	return map[string]string{"asservat.io/resource-root-uid": a.Input.Resources.UID, "asservat.io/resource-setup-id": a.Input.ResourceSetupID, ownerIdentityProjectionMarker: p.OperationID}
}

// Child provenance is additional to the immutable parent projection intent.
func ownerIdentityReaderAnnotations(a contracts.OwnerIdentityActivation, p *contracts.OwnerIdentityProjectionClaim, child *contracts.OwnerIdentityObjectAttempt) map[string]string {
	v := ownerIdentityAnnotations(a, p)
	if child != nil {
		v["asservat.io/owner-identity-object"] = child.OperationID
	}
	return v
}

func (s *InstalledOwnerIdentityReader) projections(ctx context.Context, state contracts.InitialRuntimeResourceState, m contracts.OwnerIdentityCredentialManifest, mounted map[string][]byte) (err error) {
	check := ownerReadProjectionReceipt
	defer ownerReadAnnotate(&check, &err)
	in, p := s.activation.Input, state.OwnerIdentity
	if p == nil || p.Receipt == nil || p.Configuration == nil || p.Credentials == nil {
		return cfg.ErrUnavailable
	}
	prefix := "/api/v1/namespaces/" + in.Namespace.Name
	check = ownerReadConfigurationRead
	var config core.ConfigMap
	if e := s.get(ctx, prefix+"/configmaps/"+p.Receipt.Configuration.Name, &config); e != nil {
		return e
	}
	check = ownerReadConfigurationMetadata
	if config.APIVersion != "v1" || config.Kind != "ConfigMap" || !ownerMetadata(config.ObjectMeta, in.Namespace.Name, p.Receipt.Configuration.Name, p.Receipt.Configuration.UID) || config.ResourceVersion != p.Receipt.ConfigurationResourceVersion || config.Immutable == nil || !*config.Immutable || len(config.OwnerReferences) != 0 || len(config.Finalizers) != 0 || len(config.Labels) != 0 || !equalJSON(config.Annotations, ownerIdentityReaderAnnotations(s.activation, p, p.Configuration)) || len(config.BinaryData) != 0 || len(config.Data) != 1 {
		return cfg.ErrChanged
	}
	check = ownerReadConfigurationContent
	parsed, e := contracts.DecodeOwnerDeployment(bytes.NewBufferString(config.Data["deployment.json"]))
	if e != nil || !equalJSON(parsed, s.input) {
		return cfg.ErrChanged
	}
	check = ownerReadConfigurationDigest
	digest, e := ownerIdentityPublicDigest(parsed, m)
	if e != nil || digest != p.PublicDigest {
		return cfg.ErrChanged
	}
	check = ownerReadCredentialsRead
	var secret core.Secret
	if e = s.get(ctx, prefix+"/secrets/"+p.Receipt.Credentials.Name, &secret); e != nil {
		return e
	}
	defer clearRuntimeProjection(secret.Data)
	check = ownerReadCredentialsMetadata
	keys := ownerIdentityProjectionKeys(s.input)
	if secret.APIVersion != "v1" || secret.Kind != "Secret" || !ownerMetadata(secret.ObjectMeta, in.Namespace.Name, p.Receipt.Credentials.Name, p.Receipt.Credentials.UID) || secret.ResourceVersion != p.Receipt.CredentialsResourceVersion || secret.Immutable == nil || !*secret.Immutable || secret.Type != core.SecretTypeOpaque || len(secret.OwnerReferences) != 0 || len(secret.Finalizers) != 0 || len(secret.Labels) != 0 || !equalJSON(secret.Annotations, ownerIdentityReaderAnnotations(s.activation, p, p.Credentials)) || len(secret.StringData) != 0 || len(secret.Data) != len(keys) || len(mounted) != len(keys) {
		return cfg.ErrChanged
	}
	check = ownerReadCredentialsContent
	for _, key := range keys {
		if len(mounted[key]) == 0 || len(mounted[key]) > contracts.OwnerIdentityRoleMaxBytes || !bytes.Equal(secret.Data[key], mounted[key]) {
			return cfg.ErrChanged
		}
	}
	check = ownerReadCredentialsManifest
	actual, e := contracts.DecodeOwnerIdentityCredentialManifest(bytes.NewReader(secret.Data[contracts.OwnerIdentityRoleManifestFile]))
	if e != nil || !equalJSON(actual, m) {
		return cfg.ErrChanged
	}
	return nil
}

func ownerIdentitySpecDigest(d apps.Deployment) (string, error) {
	b, e := json.Marshal(d.Spec)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func (s *InstalledOwnerIdentityReader) deployment(ctx context.Context, state contracts.InitialRuntimeResourceState) (err error) {
	check := ownerReadLaunchReceipt
	defer ownerReadAnnotate(&check, &err)
	in, l := s.activation.Input, state.OwnerLaunch
	if l == nil || l.Receipt == nil {
		return cfg.ErrUnavailable
	}
	check = ownerReadDeploymentRead
	var d apps.Deployment
	if e := s.get(ctx, "/apis/apps/v1/namespaces/"+in.Namespace.Name+"/deployments/"+in.Deployment.Name, &d); e != nil {
		return e
	}
	check = ownerReadDeploymentMetadata
	if d.APIVersion != "apps/v1" || d.Kind != "Deployment" || !ownerMetadata(d.ObjectMeta, in.Namespace.Name, in.Deployment.Name, in.Deployment.UID) || d.Generation != l.Receipt.Generation || d.ResourceVersion == l.InertResourceVersion || len(d.Spec.Template.Spec.Containers) != 1 || d.Spec.Replicas == nil || *d.Spec.Replicas != 1 || d.Annotations[initialRuntimeResourceMarker] != state.Objects[10].OperationID || d.Annotations[ownerIdentityLaunchMarker] != l.OperationID {
		return cfg.ErrChanged
	}
	check = ownerReadDeploymentRevision
	count := 2
	if revision, ok := d.Annotations["deployment.kubernetes.io/revision"]; ok {
		if revision != "1" {
			return cfg.ErrChanged
		}
		count++
	}
	check = ownerReadDeploymentAnnotations
	if len(d.Annotations) != count {
		return cfg.ErrChanged
	}
	check = ownerReadDeploymentRunningDigest
	running, e := ownerIdentitySpecDigest(d)
	if e != nil || running != l.RunningDigest {
		return cfg.ErrChanged
	}
	check = ownerReadDeploymentInertDigest
	copy := d.DeepCopy()
	*copy.Spec.Replicas = 0
	inert, e := ownerIdentitySpecDigest(*copy)
	if e != nil || inert != l.InertDigest {
		return cfg.ErrChanged
	}
	n := runtimeResourceNames(in.InstallationID)
	plan := OwnerWorkloadPlan{InstallationID: in.InstallationID, Namespace: in.Namespace.Name, Name: n.Owner, ServiceAccount: n.Owner, Configuration: n.OwnerInputs, Credentials: n.OwnerProviders, WorkloadGuard: n.WorkloadGuard, Image: d.Spec.Template.Spec.Containers[0].Image}
	var want *OwnerWorkload
	check = ownerReadDeploymentProviderBinding
	if in.OwnerLayout == contracts.OwnerProviderInstalledLayout {
		if !ownerProviderJournalBound(s.input, s.activation, state) {
			return cfg.ErrChanged
		}
		want, e = BuildProviderOwnerWorkload(plan, in.ClusterID, *state.OwnerProvider)
	} else {
		want, e = BuildInstalledOwnerWorkload(plan)
	}
	check = ownerReadDeploymentTemplateDigest
	if e != nil || preparationDigest(want.Deployment) != state.Objects[10].TemplateDigest || preparationDigest(want.Account) != state.Objects[0].TemplateDigest {
		return cfg.ErrChanged
	}
	check = ownerReadDeploymentTemplate
	copy.Annotations = nil
	if normalizeInitialRuntimeObject(copy) != nil || normalizeInitialRuntimeObject(want.Deployment) != nil || !equalJSON(copy, want.Deployment) {
		return cfg.ErrChanged
	}
	check = ownerReadAccountRead
	var account core.ServiceAccount
	if e = s.get(ctx, "/api/v1/namespaces/"+in.Namespace.Name+"/serviceaccounts/"+in.ServiceAccount.Name, &account); e != nil {
		return e
	}
	check = ownerReadAccountContent
	c := state.Objects[0]
	return workerOriginalObject(&account, want.Account, contracts.PublicRuntimeWorkerObject{Reference: in.ServiceAccount, OperationID: c.OperationID, TemplateDigest: c.TemplateDigest}, in.Namespace.Name)
}

// VerifyPublicProjection compares the immutable public runtime projection with
// the mounted public root (ADR-184 decision 6, ADR-194): the referenced Secret
// must be the immutable Opaque product projection of the mounted manifest's
// role root and setup, and every one of its keys must equal the mounted file.
// The mounted root also carries the operator Secret's keys, which this
// projection never names.
func (s *InstalledOwnerIdentityReader) VerifyPublicProjection(ctx context.Context, ref contracts.WorkerObjectReference, mounted map[string][]byte) error {
	if s == nil || ctx == nil || s.input.Public == nil || ref != s.input.Public.RuntimeProjection || ref.Name != contracts.PublicRuntimeProjectionName(s.input.InstallationID) {
		return cfg.ErrInvalid
	}
	manifest, err := contracts.DecodePublicRuntimeCredentialManifest(bytes.NewReader(mounted[contracts.PublicRuntimeCredentialManifestFile]))
	if err != nil {
		return cfg.ErrChanged
	}
	in := s.activation.Input
	var secret core.Secret
	if err = s.get(ctx, "/api/v1/namespaces/"+in.Namespace.Name+"/secrets/"+ref.Name, &secret); err != nil {
		return err
	}
	defer clearRuntimeProjection(secret.Data)
	if secret.APIVersion != "v1" || secret.Kind != "Secret" || !ownerMetadata(secret.ObjectMeta, in.Namespace.Name, ref.Name, ref.UID) || secret.Immutable == nil || !*secret.Immutable || secret.Type != core.SecretTypeOpaque ||
		len(secret.OwnerReferences) != 0 || len(secret.Finalizers) != 0 || len(secret.StringData) != 0 || len(secret.Data) == 0 ||
		secret.Annotations["asservat.io/role-root-uid"] != manifest.RootUID || secret.Annotations["asservat.io/role-setup-id"] != manifest.SetupID {
		return cfg.ErrChanged
	}
	for key, value := range secret.Data {
		if len(value) == 0 || !bytes.Equal(value, mounted[key]) {
			return cfg.ErrChanged
		}
	}
	return nil
}
