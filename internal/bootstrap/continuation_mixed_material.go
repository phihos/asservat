package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

// The existing named private material reader, shared by serving/identity and
// the explicitly selected external storage fields. No provider token is read.
func (k *InstallerContinuation) smallInstallerSecretReader(ctx context.Context) (func(string) (*core.Secret, error), error) {
	fail := func(step string) error {
		return &fixedStepError{step: "owner-material/" + step, err: mounts.ErrUnavailable}
	}
	if k == nil || k.in == nil || !initialOpenBaoCurrent(ctx) || len(validation.IsDNS1123Label(k.input.Namespace)) != 0 {
		return nil, fail("source")
	}
	config := k.in.kubernetes("administrator-token")
	client, e := rest.HTTPClientFor(config)
	if e != nil {
		return nil, fail("client")
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	api, e := coreclient.NewForConfigAndClient(config, client)
	if e != nil {
		return nil, fail("client")
	}
	read := func(name string) (*core.Secret, error) {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return nil, fail("source")
		}
		stream, e := api.RESTClient().Get().AbsPath("/api/v1/namespaces/"+k.input.Namespace+"/secrets/"+name).SetHeader("Accept", "application/json").MaxRetries(0).Stream(ctx)
		if e != nil {
			return nil, fail("read")
		}
		defer stream.Close()
		raw, e := io.ReadAll(io.LimitReader(stream, (1<<20)+1))
		defer clear(raw)
		var secret core.Secret
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if e != nil || len(raw) > 1<<20 || decoder.Decode(&secret) != nil || decoder.Decode(new(any)) != io.EOF || !initialOpenBaoCurrent(ctx) {
			for _, value := range secret.Data {
				clear(value)
			}
			return nil, fail("decode")
		}
		if secret.APIVersion != "v1" || secret.Kind != "Secret" || secret.Name != name || secret.Namespace != k.input.Namespace || !authorization.UUID(string(secret.UID)) || !identity.Text(secret.ResourceVersion, 128) || secret.DeletionTimestamp != nil || (secret.Type != core.SecretTypeOpaque && secret.Type != core.SecretTypeTLS) || len(secret.StringData) != 0 {
			for _, value := range secret.Data {
				clear(value)
			}
			return nil, fail("metadata")
		}
		return &secret, nil
	}

	return read, nil
}

// External storage credentials use the existing closed inbox names. The fixed
// phase1 worker file is separate from the owner's phase3 audit-storage.json.
func (k *InstallerContinuation) mixedExternalStorageData(ctx context.Context, phase int, artifact []byte) (map[string][]byte, error) {
	if k.input.MaterialSecretName == "" {
		return nil, &fixedStepError{step: "external-storage/material-source-required", err: mounts.ErrUnavailable}
	}
	read, err := k.smallInstallerSecretReader(ctx)
	if err != nil {
		return nil, err
	}
	source, err := read(k.input.MaterialSecretName)
	if err != nil {
		return nil, err
	}
	defer clearMixedInstallerData(source.Data)
	data := map[string][]byte{contracts.InstallerInboxPhase: []byte("1")}
	if phase == 1 {
		data[contracts.InstallerInboxAuditCredential] = bytes.Clone(source.Data[contracts.ConfigurationProviderAuditCredentialFile])
	} else if phase == 3 {
		plan, err := readInstallerProviderMaterialPlan(artifact)
		if err != nil {
			return nil, err
		}
		data, err = k.smallOwnerMaterialFromSource(ctx, plan.ServingTLS, source)
		if err != nil {
			return nil, err
		}
		data[contracts.InstallerInboxPhase] = []byte("3")
		for _, key := range []string{contracts.InstallerInboxAuditCredential, contracts.InstallerInboxFederationAuditCredential, contracts.InstallerInboxPublisherAuditCredential, contracts.InstallerInboxEvidenceReadCredential, contracts.InstallerInboxDownloadEvidenceCredential, contracts.InstallerInboxEvidenceDeleteCredential, contracts.InstallerInboxCleanupAuditCredential, contracts.InstallerInboxCleanupVerifyCredential} {
			if raw, present := source.Data[key]; present {
				data[key] = bytes.Clone(raw)
			}
		}
	} else {
		return nil, mounts.ErrUnavailable
	}
	if err := mixedInstallerDataMatchesRecipe(phase, artifact, data); err != nil {
		clearMixedInstallerData(data)
		return nil, err
	}
	return data, nil
}
