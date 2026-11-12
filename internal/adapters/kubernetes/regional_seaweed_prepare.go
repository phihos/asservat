package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	authn "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// PrepareRegionalSeaweedStorage persists the two original regional keys before
// the explicitly selected bundled installer enables IAM or installs a connector.
// It reuses the existing immutable RegionalEvidence Secret and namespace marker;
// it installs no IAM and grants no execution or evidence authority. The trusted
// caller selects the actual offer and serializes provider administration.
func PrepareRegionalSeaweedStorage(ctx context.Context, config *rest.Config, p RegionalInstallPlan) (evidence, history []byte, failure error) {
	step := "storage-plan"
	defer func() {
		if failure != nil {
			clear(evidence)
			clear(history)
			evidence, history = nil, nil
			failure = &regionalInstallError{step: step, cause: failure}
		}
	}()
	offered, err := p.Offer.RegionalExecutorOffered()
	if ctx == nil || config == nil || !p.Bootstrap.Valid() || !offered || err != nil || len(validation.IsDNS1123Label(p.Namespace)) != 0 {
		return nil, nil, cfg.ErrInvalid
	}
	call, end := context.WithDeadline(ctx, p.Bootstrap.NotAfter)
	defer end()
	current := func() bool {
		now := time.Now()
		return call.Err() == nil && !now.Before(p.Bootstrap.NotBefore) && now.Before(p.Bootstrap.NotAfter)
	}
	if !current() {
		return nil, nil, cfg.ErrUnavailable
	}
	api, err := installerAPI(config)
	if err != nil {
		return nil, nil, cfg.ErrInvalid
	}
	step = "storage-identity"
	who, err := api.AuthenticationV1().SelfSubjectReviews().Create(call, &authn.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil || !current() || !identity.Text(who.Status.UserInfo.Username, 253) || strings.HasPrefix(who.Status.UserInfo.Username, "system:serviceaccount:") && !p.AccountAdministrator {
		return nil, nil, cfg.ErrUnavailable
	}
	if who.Status.UserInfo.Username == "system:serviceaccount:"+p.Namespace+":"+RegionalAccount {
		return nil, nil, cfg.ErrInvalid
	}
	marker := p.Offer.InstallationID + "/" + p.Bootstrap.Binding.ClusterID
	secretAPI := api.CoreV1().RESTClient()
	read := func() (*core.Secret, error) {
		s := &core.Secret{}
		err := secretAPI.Get().Namespace(p.Namespace).Resource("secrets").Name(RegionalEvidence).MaxRetries(0).Do(call).Into(s)
		return s, err
	}
	step = "storage-original"
	stored, err := read()
	if !current() {
		return nil, nil, cfg.ErrUnavailable
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, nil, cfg.ErrUnavailable
	}
	if err == nil {
		defer clearSmallSeaweedData(stored.Data)
		p.Evidence, p.History = bytes.Clone(stored.Data["evidence-storage.json"]), bytes.Clone(stored.Data[contracts.RegionalHistoryCredentialFile])
		defer clear(p.Evidence)
		defer clear(p.History)
		if !regionalSeaweedPlanValid(p) || !regionalSeaweedSecretMatches(stored, p, marker) {
			return nil, nil, cfg.ErrChanged
		}
	} else {
		// Typed clients can return an allocated empty result alongside 404.
		stored = nil
		// Existing state is inspected first: retries never create replacement keys.
		for i, purpose := range []string{"regional-write", "regional-history"} {
			c, e := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: p.Bootstrap.Binding.ClusterID})
			if e != nil {
				return nil, nil, cfg.ErrUnavailable
			}
			runtime, e := providerconfig.SeaweedRuntimeCredential(c)
			if e != nil {
				return nil, nil, cfg.ErrInvalid
			}
			raw, e := json.Marshal(runtime)
			if e != nil {
				return nil, nil, cfg.ErrUnavailable
			}
			if i == 0 {
				p.Evidence = raw
				defer clear(p.Evidence)
			} else {
				p.History = raw
				defer clear(p.History)
			}
		}
		if !regionalSeaweedPlanValid(p) {
			return nil, nil, cfg.ErrInvalid
		}
	}
	// Validate the complete typed plan before either namespace or Secret effects.
	if !current() {
		return nil, nil, cfg.ErrUnavailable
	}
	step = "storage-namespace"
	if _, err = ensureRegional(call, api.CoreV1().Namespaces(), &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: p.Namespace, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "latest"}}}, marker); err != nil {
		return nil, nil, err
	}
	if !current() {
		return nil, nil, cfg.ErrUnavailable
	}
	if stored == nil {
		step = "storage-create"
		want := regionalSeaweedSecret(p, marker)
		created := &core.Secret{}
		e := secretAPI.Post().Namespace(p.Namespace).Resource("secrets").Body(want).MaxRetries(0).Do(call).Into(created)
		if e != nil || !regionalSeaweedSecretMatches(created, p, marker) {
			// One exact lookup resolves transport errors and malformed successful bodies.
			// It never retries the mutation or accepts a different caller's candidate.
			if !current() {
				return nil, nil, cfg.ErrUnavailable
			}
			if created != nil {
				clearSmallSeaweedData(created.Data)
			}
			created, e = read()
		}
		if created != nil {
			defer clearSmallSeaweedData(created.Data)
		}
		if e != nil {
			return nil, nil, cfg.ErrUnavailable
		}
		if !regionalSeaweedSecretMatches(created, p, marker) {
			return nil, nil, cfg.ErrChanged
		}
	}
	if !current() {
		return nil, nil, cfg.ErrUnavailable
	}
	return bytes.Clone(p.Evidence), bytes.Clone(p.History), nil
}

func regionalSeaweedPlanValid(p RegionalInstallPlan) bool {
	if !p.valid() {
		return false
	}
	for i, raw := range [][]byte{p.Evidence, p.History} {
		c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(raw))
		if err != nil || c.SessionToken != "" {
			return false
		}
		purpose := []string{"regional-write", "regional-history"}[i]
		if providerconfig.ValidateSeaweedCredential(contracts.SeaweedCredential{Principal: contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: p.Bootstrap.Binding.ClusterID}, AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey}) != nil {
			return false
		}
	}
	return !bytes.Equal(p.Evidence, p.History)
}
func regionalSeaweedSecret(p RegionalInstallPlan, marker string) *core.Secret {
	data := map[string][]byte{"evidence-storage.json": p.Evidence, contracts.RegionalHistoryCredentialFile: p.History}
	if len(p.ProfileAuthorization) > 0 {
		data[contracts.RegionalProfileAuthorizationFile] = p.ProfileAuthorization
	}
	s := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: RegionalEvidence}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: data}
	raw, _ := json.Marshal(*s)
	defer clear(raw)
	digest := sha256.Sum256(raw)
	s.Annotations = map[string]string{regionalInstall: marker, regionalTemplate: hex.EncodeToString(digest[:])}
	return s
}
func regionalSeaweedSecretMatches(s *core.Secret, p RegionalInstallPlan, marker string) bool {
	if s == nil || s.Name != RegionalEvidence || s.Namespace != p.Namespace || !authorization.UUID(string(s.UID)) || s.ResourceVersion == "" || s.DeletionTimestamp != nil || len(s.OwnerReferences) != 0 || len(s.Finalizers) != 0 || len(s.Labels) != 0 || s.Type != core.SecretTypeOpaque || s.Immutable == nil || !*s.Immutable || len(s.StringData) != 0 {
		return false
	}
	want := regionalSeaweedSecret(p, marker)
	return reflect.DeepEqual(s.Annotations, want.Annotations) && reflect.DeepEqual(s.Data, want.Data)
}
