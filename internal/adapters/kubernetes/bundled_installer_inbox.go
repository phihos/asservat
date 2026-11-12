package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

const BundledInstallerInboxRecipeAnnotation = "asservat.io/provider-recipe-sha256"
const bundledInstallerInboxRole = "bundled-installer-inbox"

func bundledInboxContextCurrent(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	until, ok := ctx.Deadline()
	return ok && time.Now().Before(until)
}
func bundledInboxDataValid(data map[string][]byte, tokenAllowed bool) bool {
	if string(data[contracts.InstallerInboxPhase]) != "3" || len(data[contracts.InstallerInboxAuditCredential]) == 0 {
		return false
	}
	allowed := map[string]int{contracts.InstallerInboxPhase: 1}
	for _, key := range []string{contracts.InstallerInboxAuditCredential, contracts.InstallerInboxFederationAuditCredential, contracts.InstallerInboxPublisherAuditCredential, contracts.InstallerInboxEvidenceReadCredential, contracts.InstallerInboxDownloadEvidenceCredential, contracts.InstallerInboxEvidenceDeleteCredential, contracts.InstallerInboxCleanupAuditCredential, contracts.InstallerInboxCleanupVerifyCredential} {
		allowed[key] = 32 << 10
		if raw, present := data[key]; present {
			c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(raw))
			if err != nil || !identity.Text(c.AccessKeyID, 256) || !identity.Text(c.SecretAccessKey, 8192) || c.SessionToken != "" {
				return false
			}
		}
	}
	public := contracts.InstallerInboxPublicFiles()
	for _, key := range public {
		allowed[key] = 64 << 10
	}
	tlsFiles := map[string][]byte{}
	for _, key := range contracts.InstallerInboxServingTLSFiles() {
		allowed[key] = 64 << 10
		if raw, present := data[key]; present {
			tlsFiles[key] = raw
		}
	}
	if !installerServingTLSFilesValid(tlsFiles) {
		return false
	}
	for _, group := range [][]string{public, {contracts.InstallerInboxPublisherAuditCredential, contracts.InstallerInboxEvidenceReadCredential}, {contracts.InstallerInboxCleanupAuditCredential, contracts.InstallerInboxCleanupVerifyCredential}} {
		count := 0
		for _, key := range group {
			if _, present := data[key]; present {
				count++
			}
		}
		if count != 0 && count != len(group) {
			return false
		}
	}
	if tokenAllowed {
		allowed[contracts.InstallerInboxInspectionToken] = 4096
	}
	total := 0
	for key, raw := range data {
		limit, known := allowed[key]
		if !known || len(raw) == 0 || len(raw) > limit {
			return false
		}
		total += len(raw)
		if total > 1<<20 {
			return false
		}
	}
	if raw, present := data[contracts.InstallerInboxInspectionToken]; present {
		for _, b := range raw {
			if b < 0x21 || b > 0x7e {
				return false
			}
		}
	}
	return true
}
func bundledInboxSecretValid(s *core.Secret, namespace, installation, digest string) bool {
	return s != nil && s.APIVersion == "v1" && s.Kind == "Secret" && s.Name == contracts.InstallerInboxName(installation) && s.Namespace == namespace && authorization.UUID(string(s.UID)) && identity.Text(s.ResourceVersion, 128) && s.DeletionTimestamp == nil && (s.Immutable == nil || !*s.Immutable) && s.Type == core.SecretTypeOpaque && len(s.StringData) == 0 && len(s.OwnerReferences) == 0 && len(s.Finalizers) == 0 && len(s.Labels) == 1 && s.Labels["asservat.io/private-role"] == bundledInstallerInboxRole && len(s.Annotations) == 1 && s.Annotations[BundledInstallerInboxRecipeAnnotation] == digest && bundledInboxDataValid(s.Data, true)
}
func bundledInboxSelectedKeys(a, b map[string][]byte) bool {
	count := 0
	for key := range a {
		if key == contracts.InstallerInboxInspectionToken {
			continue
		}
		if _, ok := b[key]; !ok {
			return false
		}
		count++
	}
	for key := range b {
		if key != contracts.InstallerInboxInspectionToken {
			count--
		}
	}
	return count == 0
}
func bundledInboxInputValid(ctx context.Context, config *rest.Config, namespace, installation, digest string) bool {
	return config != nil && len(validation.IsDNS1123Label(namespace)) == 0 && authorization.UUID(installation) && preparationDigestValid(digest) && bundledInboxContextCurrent(ctx)
}
func readBundledInbox(ctx context.Context, api rest.Interface, namespace, installation, digest string) (*core.Secret, error) {
	raw, err := api.Get().AbsPath("/api/v1/namespaces/" + namespace + "/secrets/" + contracts.InstallerInboxName(installation)).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, err
		}
		return nil, cfg.ErrUnavailable
	}
	var s core.Secret
	if len(raw) > 2<<20 || strictGuardJSON(raw, &s) != nil || !bundledInboxSecretValid(&s, namespace, installation, digest) {
		clearSmallSeaweedData(s.Data)
		return nil, cfg.ErrChanged
	}
	if !bundledInboxContextCurrent(ctx) {
		clearSmallSeaweedData(s.Data)
		return nil, cfg.ErrUnavailable
	}
	return &s, nil
}

// ReadOrCreateBundledInstallerInbox retains the existing phase-3 inbox as a key
// carrier before IAM activation. Only a protected caller selects the recipe and
// validates actual principal scopes/material. Existing bytes win; this helper
// grants no authority and never overwrites an earlier candidate or makes a token.
func ReadOrCreateBundledInstallerInbox(ctx context.Context, config *rest.Config, namespace, installation, recipeDigest string, candidate map[string][]byte) (*core.Secret, error) {
	if !bundledInboxInputValid(ctx, config, namespace, installation, recipeDigest) || !bundledInboxDataValid(candidate, false) {
		return nil, cfg.ErrInvalid
	}
	api, err := newBoundedAPI(config)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	existing, err := readBundledInbox(ctx, api, namespace, installation, recipeDigest)
	if err == nil {
		if !bundledInboxSelectedKeys(existing.Data, candidate) {
			clearSmallSeaweedData(existing.Data)
			return nil, cfg.ErrChanged
		}
		return existing, nil
	}
	if !apierrors.IsNotFound(err) {
		if err == cfg.ErrChanged {
			return nil, err
		}
		return nil, cfg.ErrUnavailable
	}
	if !bundledInboxContextCurrent(ctx) {
		return nil, cfg.ErrUnavailable
	}
	request := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: contracts.InstallerInboxName(installation), Namespace: namespace, Labels: map[string]string{"asservat.io/private-role": bundledInstallerInboxRole}, Annotations: map[string]string{BundledInstallerInboxRecipeAnnotation: recipeDigest}}, Type: core.SecretTypeOpaque, Data: maps.Clone(candidate)}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	defer clear(body)
	raw, createErr := api.Post().AbsPath("/api/v1/namespaces/"+namespace+"/secrets").Param("fieldValidation", "Strict").Body(body).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	var created core.Secret
	if createErr == nil && len(raw) <= 2<<20 && strictGuardJSON(raw, &created) == nil && bundledInboxSecretValid(&created, namespace, installation, recipeDigest) && maps.EqualFunc(created.Data, candidate, bytes.Equal) && bundledInboxContextCurrent(ctx) {
		return &created, nil
	}
	clearSmallSeaweedData(created.Data)
	// Lost/malformed CREATE replies allow one exact named lookup only. A valid
	// racing original wins, but selection drift and foreign objects do not.
	winner, err := readBundledInbox(ctx, api, namespace, installation, recipeDigest)
	if err != nil {
		if err == cfg.ErrChanged {
			return nil, err
		}
		return nil, cfg.ErrUnavailable
	}
	if !bundledInboxSelectedKeys(winner.Data, candidate) {
		clearSmallSeaweedData(winner.Data)
		return nil, cfg.ErrChanged
	}
	return winner, nil
}

// CompleteBundledInstallerInbox changes only the inspection token on the exact
// returned original UID/RV. A new real token may replace an expired one; storage
// and supplied public/TLS material remain byte-identical. No mutation is retried.
func CompleteBundledInstallerInbox(ctx context.Context, config *rest.Config, namespace, installation, recipeDigest string, original *core.Secret, inspectionToken []byte) (*core.Secret, error) {
	if !bundledInboxInputValid(ctx, config, namespace, installation, recipeDigest) || !bundledInboxSecretValid(original, namespace, installation, recipeDigest) || len(inspectionToken) == 0 || len(inspectionToken) > 4096 {
		return nil, cfg.ErrInvalid
	}
	for _, b := range inspectionToken {
		if b < 0x21 || b > 0x7e {
			return nil, cfg.ErrInvalid
		}
	}
	api, err := newBoundedAPI(config)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	current, err := readBundledInbox(ctx, api, namespace, installation, recipeDigest)
	if err != nil {
		if err == cfg.ErrChanged {
			return nil, err
		}
		return nil, cfg.ErrUnavailable
	}
	defer clearSmallSeaweedData(current.Data)
	if current.UID != original.UID || current.ResourceVersion != original.ResourceVersion || !maps.EqualFunc(current.Data, original.Data, bytes.Equal) {
		return nil, cfg.ErrChanged
	}
	if bytes.Equal(current.Data[contracts.InstallerInboxInspectionToken], inspectionToken) {
		return current.DeepCopy(), nil
	}
	current.Data[contracts.InstallerInboxInspectionToken] = bytes.Clone(inspectionToken)
	body, err := json.Marshal(current)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	defer clear(body)
	if !bundledInboxContextCurrent(ctx) {
		return nil, cfg.ErrUnavailable
	}
	raw, writeErr := api.Put().AbsPath("/api/v1/namespaces/"+namespace+"/secrets/"+current.Name).Param("fieldValidation", "Strict").Body(body).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	var completed core.Secret
	if writeErr == nil && len(raw) <= 2<<20 && strictGuardJSON(raw, &completed) == nil && bundledInboxSecretValid(&completed, namespace, installation, recipeDigest) && completed.UID == original.UID && maps.EqualFunc(completed.Data, current.Data, bytes.Equal) && bundledInboxContextCurrent(ctx) {
		return &completed, nil
	}
	clearSmallSeaweedData(completed.Data)
	actual, err := readBundledInbox(ctx, api, namespace, installation, recipeDigest)
	if err != nil {
		if err == cfg.ErrChanged {
			return nil, err
		}
		return nil, cfg.ErrUnavailable
	}
	if actual.UID != original.UID || !maps.EqualFunc(actual.Data, current.Data, bytes.Equal) {
		clearSmallSeaweedData(actual.Data)
		return nil, cfg.ErrChanged
	}
	return actual, nil
}
