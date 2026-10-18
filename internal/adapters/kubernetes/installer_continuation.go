package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// installerAPI uses JSON like the other adapters' typed reads and writes.
func installerAPI(config *rest.Config) (*kubernetes.Clientset, error) {
	c := rest.CopyConfig(config)
	c.ContentType, c.AcceptContentTypes = "application/json", "application/json"
	return kubernetes.NewForConfig(c)
}

// EnsureProviderAuditSecrets allocates the two empty, protected provider audit
// Secrets whose UIDs ADR-149 binds before the first resource claim. An existing
// Secret is accepted only while still empty, so a rerun cannot adopt material.
func EnsureProviderAuditSecrets(ctx context.Context, config *rest.Config, namespace, installation string) (worker, owner contracts.WorkerObjectReference, err error) {
	if ctx == nil || config == nil || !authorization.UUID(installation) || namespace == "" {
		return worker, owner, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return worker, owner, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	names := runtimeResourceNames(installation)
	refs := make([]contracts.WorkerObjectReference, 2)
	for i, name := range []string{names.WorkerProviders, contracts.OwnerProviderAuditSecretName(installation)} {
		secret, e := api.CoreV1().Secrets(namespace).Create(call, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: name}, Type: core.SecretTypeOpaque}, meta.CreateOptions{})
		if apierrors.IsAlreadyExists(e) {
			secret, e = api.CoreV1().Secrets(namespace).Get(call, name, meta.GetOptions{})
			if e == nil && (len(secret.Data) != 0 || len(secret.StringData) != 0 || secret.Type != core.SecretTypeOpaque) {
				return worker, owner, cfg.ErrChanged
			}
		}
		if e != nil || secret.Name != name || !authorization.UUID(string(secret.UID)) {
			return worker, owner, cfg.ErrUnavailable
		}
		refs[i] = contracts.WorkerObjectReference{Name: secret.Name, UID: string(secret.UID)}
	}
	return refs[0], refs[1], nil
}

// PublishInstallerRecipe writes the public recipe outbox (ADR-183). It holds
// no credential; an existing outbox is replaced only for a later phase.
func PublishInstallerRecipe(ctx context.Context, config *rest.Config, namespace, installation string, outbox contracts.InstallerRecipeOutbox) error {
	if ctx == nil || config == nil || !authorization.UUID(installation) || namespace == "" || outbox.Format != contracts.InstallerRecipeOutboxFormat || outbox.Phase < 1 || outbox.Phase > 4 || len(outbox.Recipe) == 0 {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	body, err := json.Marshal(outbox)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	name := contracts.InstallerRecipeOutboxName(installation)
	object := &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: name}, Data: map[string]string{"outbox.json": string(body)}}
	if _, err = api.CoreV1().ConfigMaps(namespace).Create(call, object, meta.CreateOptions{}); apierrors.IsAlreadyExists(err) {
		current, e := api.CoreV1().ConfigMaps(namespace).Get(call, name, meta.GetOptions{})
		if e != nil {
			return cfg.ErrUnavailable
		}
		var previous contracts.InstallerRecipeOutbox
		if json.Unmarshal([]byte(current.Data["outbox.json"]), &previous) != nil || previous.Phase > outbox.Phase {
			return cfg.ErrChanged
		}
		current.Data = object.Data
		_, err = api.CoreV1().ConfigMaps(namespace).Update(call, current, meta.UpdateOptions{})
	}
	if err != nil {
		return cfg.ErrUnavailable
	}
	return nil
}

// MintAccountToken issues one bounded token for an installer-owned runtime
// account with the original probe audience (ADR-183). The caller holds it
// only for the current continuation phase.
func MintAccountToken(ctx context.Context, config *rest.Config, namespace, account, audience string) ([]byte, error) {
	if ctx == nil || config == nil || namespace == "" || account == "" || audience == "" {
		return nil, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	seconds := int64(600)
	result, err := api.CoreV1().ServiceAccounts(namespace).CreateToken(call, account, &authv1.TokenRequest{Spec: authv1.TokenRequestSpec{Audiences: []string{audience}, ExpirationSeconds: &seconds}}, meta.CreateOptions{})
	if err != nil || result.Status.Token == "" {
		return nil, cfg.ErrUnavailable
	}
	return []byte(result.Status.Token), nil
}

// InstallerInbox is the operator's answer to one published recipe.
type InstallerInbox struct {
	UID             string
	InspectionToken []byte
	AuditCredential []byte
	// FederationAuditCredential is present when the phase-3 artifact carried
	// the federation setup (ADR-193).
	FederationAuditCredential []byte
	// PublisherAuditCredential and EvidenceReadCredential are present when the
	// phase-3 artifact carried the publisher setup (ADR-203).
	PublisherAuditCredential, EvidenceReadCredential []byte
	// Public holds exactly the InstallerInboxPublicFiles when the phase-3
	// artifact carried a promoted owner (ADR-194); otherwise it is nil.
	Public map[string][]byte
}

// ReadInstallerInbox returns the inbox only when it answers phase; any other
// state is unavailable so the caller keeps waiting within its deadline.
func ReadInstallerInbox(ctx context.Context, config *rest.Config, namespace, installation string, phase int) (InstallerInbox, error) {
	var zero InstallerInbox
	if ctx == nil || config == nil || namespace == "" || !authorization.UUID(installation) || phase < 1 || phase > 4 {
		return zero, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return zero, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	s, err := api.CoreV1().Secrets(namespace).Get(call, contracts.InstallerInboxName(installation), meta.GetOptions{})
	if err != nil || s.Type != core.SecretTypeOpaque || string(s.Data[contracts.InstallerInboxPhase]) != strconv.Itoa(phase) || len(s.Data[contracts.InstallerInboxInspectionToken]) == 0 || len(s.Data[contracts.InstallerInboxAuditCredential]) == 0 || !authorization.UUID(string(s.UID)) {
		return zero, cfg.ErrUnavailable
	}
	out := InstallerInbox{UID: string(s.UID), InspectionToken: s.Data[contracts.InstallerInboxInspectionToken], AuditCredential: s.Data[contracts.InstallerInboxAuditCredential],
		FederationAuditCredential: s.Data[contracts.InstallerInboxFederationAuditCredential],
		PublisherAuditCredential:  s.Data[contracts.InstallerInboxPublisherAuditCredential], EvidenceReadCredential: s.Data[contracts.InstallerInboxEvidenceReadCredential]}
	for _, key := range contracts.InstallerInboxPublicFiles() {
		if v := s.Data[key]; len(v) != 0 {
			if out.Public == nil {
				out.Public = map[string][]byte{}
			}
			out.Public[key] = v
		}
	}
	return out, nil
}

// DeleteInstallerInbox removes exactly the consumed inbox.
func DeleteInstallerInbox(ctx context.Context, config *rest.Config, namespace, installation, uid string) error {
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	id := types.UID(uid)
	err = api.CoreV1().Secrets(namespace).Delete(call, contracts.InstallerInboxName(installation), meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &id}})
	if err != nil && !apierrors.IsNotFound(err) {
		return cfg.ErrUnavailable
	}
	return nil
}

// FillProviderAuditSecret writes the scoped audit storage credential into the
// original empty Secret. A rerun after an unknown write accepts only the exact
// same content; any other material is a change.
func FillProviderAuditSecret(ctx context.Context, config *rest.Config, namespace string, ref contracts.WorkerObjectReference, file string, payload []byte) error {
	if ctx == nil || config == nil || namespace == "" || file == "" || len(payload) == 0 || !authorization.UUID(ref.UID) {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	s, err := api.CoreV1().Secrets(namespace).Get(call, ref.Name, meta.GetOptions{})
	if err != nil || string(s.UID) != ref.UID || s.Type != core.SecretTypeOpaque {
		return cfg.ErrUnavailable
	}
	if len(s.Data) != 0 {
		if len(s.Data) == 1 && bytes.Equal(s.Data[file], payload) {
			return nil
		}
		return cfg.ErrChanged
	}
	s.Data = map[string][]byte{file: payload}
	if _, err = api.CoreV1().Secrets(namespace).Update(call, s, meta.UpdateOptions{}); err != nil {
		return cfg.ErrUnavailable
	}
	return nil
}

// WriteOwnerPublicSecret creates the operator public Secret the promoted
// owner mounts beside its public runtime projection (ADR-194 decision 11).
// It is mutable so an administrator can rotate it; a rerun accepts only the
// exact same content, and anything else is a change.
func WriteOwnerPublicSecret(ctx context.Context, config *rest.Config, namespace, installation string, files map[string][]byte) error {
	if ctx == nil || config == nil || namespace == "" || !authorization.UUID(installation) || len(files) != len(contracts.InstallerInboxPublicFiles()) {
		return cfg.ErrInvalid
	}
	data := map[string][]byte{}
	for _, key := range contracts.InstallerInboxPublicFiles() {
		if len(files[key]) == 0 {
			return cfg.ErrInvalid
		}
		data[key] = files[key]
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	secrets := api.CoreV1().Secrets(namespace)
	s, err := secrets.Create(call, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: contracts.OwnerPublicProjectionName(installation)}, Type: core.SecretTypeOpaque, Data: data}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		s, err = secrets.Get(call, contracts.OwnerPublicProjectionName(installation), meta.GetOptions{})
	}
	if err != nil || s.Type != core.SecretTypeOpaque {
		return cfg.ErrUnavailable
	}
	if len(s.Data) != len(data) {
		return cfg.ErrChanged
	}
	for key, value := range data {
		if !bytes.Equal(s.Data[key], value) {
			return cfg.ErrChanged
		}
	}
	return nil
}

// ReadInstallerOutbox is the operator side's read of the published recipe.
func ReadInstallerOutbox(ctx context.Context, config *rest.Config, namespace, installation string) (contracts.InstallerRecipeOutbox, error) {
	var out contracts.InstallerRecipeOutbox
	api, err := installerAPI(config)
	if err != nil || namespace == "" || !authorization.UUID(installation) {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	c, err := api.CoreV1().ConfigMaps(namespace).Get(call, contracts.InstallerRecipeOutboxName(installation), meta.GetOptions{})
	if err != nil || json.Unmarshal([]byte(c.Data["outbox.json"]), &out) != nil || out.Format != contracts.InstallerRecipeOutboxFormat || out.Phase < 1 || out.Phase > 4 {
		return out, cfg.ErrUnavailable
	}
	return out, nil
}

// WriteInstallerInbox writes the operator's answer for phase, replacing an
// older answer in the operator-owned release namespace.
// federation is the optional federation audit credential (ADR-193), public
// the optional promoted owner's InstallerInboxPublicFiles (ADR-194) and
// publisher the optional publisher credentials keyed by their inbox keys
// (ADR-203).
func WriteInstallerInbox(ctx context.Context, config *rest.Config, namespace, installation string, phase int, token, credential, federation []byte, public, publisher map[string][]byte) error {
	api, err := installerAPI(config)
	if err != nil || namespace == "" || !authorization.UUID(installation) || len(token) == 0 || len(credential) == 0 {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	s := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: contracts.InstallerInboxName(installation)}, Type: core.SecretTypeOpaque, Data: map[string][]byte{
		contracts.InstallerInboxPhase: []byte(strconv.Itoa(phase)), contracts.InstallerInboxInspectionToken: token, contracts.InstallerInboxAuditCredential: credential}}
	if len(federation) != 0 {
		s.Data[contracts.InstallerInboxFederationAuditCredential] = federation
	}
	if publisher != nil {
		for _, key := range []string{contracts.InstallerInboxPublisherAuditCredential, contracts.InstallerInboxEvidenceReadCredential} {
			if len(publisher[key]) == 0 {
				return cfg.ErrInvalid
			}
			s.Data[key] = publisher[key]
		}
		if len(publisher) != 2 {
			return cfg.ErrInvalid
		}
	}
	if public != nil {
		if len(public) != len(contracts.InstallerInboxPublicFiles()) {
			return cfg.ErrInvalid
		}
		for _, key := range contracts.InstallerInboxPublicFiles() {
			if len(public[key]) == 0 {
				return cfg.ErrInvalid
			}
			s.Data[key] = public[key]
		}
	}
	if _, err = api.CoreV1().Secrets(namespace).Create(call, s, meta.CreateOptions{}); apierrors.IsAlreadyExists(err) {
		var current *core.Secret
		if current, err = api.CoreV1().Secrets(namespace).Get(call, s.Name, meta.GetOptions{}); err == nil {
			current.Data, current.Type = s.Data, s.Type
			_, err = api.CoreV1().Secrets(namespace).Update(call, current, meta.UpdateOptions{})
		}
	}
	if err != nil {
		return cfg.ErrUnavailable
	}
	return nil
}

// WriteOwnerObservationProjection writes the public worker-control catalog the
// owner rereads every second (ADR-184). Catalog membership grants no authority,
// so the Secret is administrator-written and replaced as workers change.
func WriteOwnerObservationProjection(ctx context.Context, config *rest.Config, namespace, installation string, trust contracts.OwnerWorkerTrust) error {
	if ctx == nil || config == nil || namespace == "" || !authorization.UUID(installation) || trust.Format != contracts.OwnerWorkerTrustFormat || trust.Controls == nil || len(trust.Controls) > 256 {
		return cfg.ErrInvalid
	}
	body, err := json.Marshal(trust)
	if err != nil {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	s := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: contracts.OwnerObservationProjectionName(installation)}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"worker-controls.json": body}}
	if _, err = api.CoreV1().Secrets(namespace).Create(call, s, meta.CreateOptions{}); apierrors.IsAlreadyExists(err) {
		var current *core.Secret
		if current, err = api.CoreV1().Secrets(namespace).Get(call, s.Name, meta.GetOptions{}); err == nil {
			if current.Type != core.SecretTypeOpaque || current.Immutable != nil && *current.Immutable {
				return cfg.ErrChanged
			}
			current.Data = s.Data
			_, err = api.CoreV1().Secrets(namespace).Update(call, current, meta.UpdateOptions{})
		}
	}
	if err != nil {
		return cfg.ErrUnavailable
	}
	return nil
}

// ReadProviderAuditSecrets reopens the two provider audit Secrets by name and
// UID after an earlier run filled them (ADR-187). The resource journal's
// binding pins these exact UIDs; a replacement Secret fails that binding.
func ReadProviderAuditSecrets(ctx context.Context, config *rest.Config, namespace, installation string) (worker, owner contracts.WorkerObjectReference, err error) {
	if ctx == nil || config == nil || !authorization.UUID(installation) || namespace == "" {
		return worker, owner, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return worker, owner, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	refs := make([]contracts.WorkerObjectReference, 2)
	for i, name := range []string{runtimeResourceNames(installation).WorkerProviders, contracts.OwnerProviderAuditSecretName(installation)} {
		secret, e := api.CoreV1().Secrets(namespace).Get(call, name, meta.GetOptions{})
		if e != nil || secret.Name != name || !authorization.UUID(string(secret.UID)) || secret.Type != core.SecretTypeOpaque {
			return worker, owner, cfg.ErrUnavailable
		}
		refs[i] = contracts.WorkerObjectReference{Name: secret.Name, UID: string(secret.UID)}
	}
	return refs[0], refs[1], nil
}

// AwaitDeploymentsSettled waits until each named Deployment's controller has
// observed its generation, reports a complete rollout, and two reads a second
// apart return the same resource version. The guard bridge releases the
// runtime controllers; their delayed status writes would otherwise change a
// resource version that the five-second role proofs pin (ADR-188). It reads
// only and grants nothing.
func AwaitDeploymentsSettled(ctx context.Context, config *rest.Config, namespace string, names ...string) error {
	if ctx == nil || config == nil || namespace == "" || len(names) == 0 {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	settled := func() (string, bool) {
		versions := ""
		for _, name := range names {
			call, end := context.WithTimeout(ctx, 5*time.Second)
			d, err := api.AppsV1().Deployments(namespace).Get(call, name, meta.GetOptions{})
			end()
			if err != nil || d.Status.ObservedGeneration != d.Generation {
				return "", false
			}
			complete := false
			for _, c := range d.Status.Conditions {
				complete = complete || c.Type == apps.DeploymentProgressing && c.Status == core.ConditionTrue && c.Reason == "NewReplicaSetAvailable"
			}
			if !complete {
				return "", false
			}
			versions += d.ResourceVersion + "/"
		}
		return versions, true
	}
	previous := ""
	for {
		versions, ok := settled()
		if ok && versions == previous {
			return nil
		}
		if !ok {
			versions = ""
		}
		previous = versions
		select {
		case <-ctx.Done():
			return errors.Join(cfg.ErrUnavailable, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}
