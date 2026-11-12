package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

// ReadOrInitializeSeaweedCredential fills only an existing protected original
// Secret. The caller owns principal/phase authority and must supply its original
// bounded context; this mechanism neither grants storage access nor installs IAM.
// Existing bytes do not independently prove the supplied principal: that pairing
// remains the protected installer caller's responsibility.
// A later call recovers the same stored key, never a fresh speculative candidate.
func ReadOrInitializeSeaweedCredential(ctx context.Context, config *rest.Config, namespace string, ref contracts.WorkerObjectReference, file string, principal contracts.SeaweedPrincipalKey) (contracts.SeaweedCredential, error) {
	var zero contracts.SeaweedCredential
	if ctx == nil || config == nil || len(validation.IsDNS1123Label(namespace)) != 0 || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 || !authorization.UUID(ref.UID) || len(validation.IsConfigMapKey(file)) != 0 || principal.Purpose == "admin" {
		return zero, cfg.ErrInvalid
	}
	if _, err := providerconfig.SeaweedPrincipalName(principal); err != nil {
		return zero, cfg.ErrInvalid
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return zero, cfg.ErrInvalid
	}
	current := func() bool { return ctx.Err() == nil && time.Now().Before(deadline) }
	if !current() {
		return zero, cfg.ErrUnavailable
	}
	api, err := newBoundedAPI(config)
	if err != nil {
		return zero, cfg.ErrInvalid
	}
	path := "/api/v1/namespaces/" + namespace + "/secrets/" + ref.Name
	valid := func(s *core.Secret) bool {
		return s.APIVersion == "v1" && s.Kind == "Secret" && s.Namespace == namespace && s.Name == ref.Name && string(s.UID) == ref.UID && s.ResourceVersion != "" && s.DeletionTimestamp == nil && s.Type == core.SecretTypeOpaque && len(s.StringData) == 0 && (s.Immutable == nil || !*s.Immutable)
	}
	read := func() (*core.Secret, error) {
		raw, e := api.Get().AbsPath(path).MaxRetries(0).DoRaw(ctx)
		defer clear(raw)
		var s core.Secret
		if e != nil || len(raw) > 64<<10 || strictGuardJSON(raw, &s) != nil {
			return nil, cfg.ErrUnavailable
		}
		if !valid(&s) {
			clearSmallSeaweedData(s.Data)
			return nil, cfg.ErrChanged
		}
		if !current() {
			clearSmallSeaweedData(s.Data)
			return nil, cfg.ErrUnavailable
		}
		return &s, nil
	}
	recover := func(s *core.Secret) (contracts.SeaweedCredential, error) {
		if len(s.Data) != 1 || len(s.Data[file]) == 0 {
			return zero, cfg.ErrChanged
		}
		runtime, e := contracts.DecodeOwnerStorageCredential(bytes.NewReader(s.Data[file]))
		if e != nil || runtime.SessionToken != "" {
			return zero, cfg.ErrChanged
		}
		c := contracts.SeaweedCredential{Principal: principal, AccessKeyID: runtime.AccessKeyID, SecretAccessKey: runtime.SecretAccessKey}
		if _, e = providerconfig.SeaweedRuntimeCredential(c); e != nil {
			return zero, cfg.ErrChanged
		}
		if !current() {
			return zero, cfg.ErrUnavailable
		}
		return c, nil
	}
	s, err := read()
	if err != nil {
		return zero, err
	}
	defer clearSmallSeaweedData(s.Data)
	if len(s.Data) != 0 {
		return recover(s)
	}
	candidate, err := providerconfig.GenerateSeaweedCredential(principal)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	runtime, err := providerconfig.SeaweedRuntimeCredential(candidate)
	if err != nil {
		return zero, cfg.ErrInvalid
	}
	payload, err := json.Marshal(runtime)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	defer clear(payload)
	s.Data = map[string][]byte{file: payload}
	body, err := json.Marshal(s)
	if err != nil || !current() {
		return zero, cfg.ErrUnavailable
	}
	defer clear(body)
	raw, writeErr := api.Put().AbsPath(path).Param("fieldValidation", "Strict").Body(body).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	var written core.Secret
	if writeErr == nil && len(raw) <= 64<<10 && strictGuardJSON(raw, &written) == nil && valid(&written) && len(written.Data) == 1 && bytes.Equal(written.Data[file], payload) && current() {
		clearSmallSeaweedData(written.Data)
		return candidate, nil
	}
	clearSmallSeaweedData(written.Data)
	// A lost or malformed response permits only exact lookup of this candidate.
	// A conflicting writer is not adopted by the rejected attempt.
	actual, err := read()
	if err != nil {
		return zero, err
	}
	defer clearSmallSeaweedData(actual.Data)
	if len(actual.Data) != 1 || !bytes.Equal(actual.Data[file], payload) {
		return zero, cfg.ErrChanged
	}
	return candidate, nil
}
