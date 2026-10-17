package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// FederationIdentity is the federation account and its empty audit Secret
// (ADR-193). The account exists before the phase-3 artifact names it; the
// Secret is filled from the phase-3 inbox.
type FederationIdentity struct {
	Account, AuditCredentials contracts.WorkerObjectReference
}

// EnsureFederationIdentity creates the fixed account and audit Secret, or
// reopens them when they match exactly. It never updates an existing object.
func EnsureFederationIdentity(ctx context.Context, config *rest.Config, namespace, installation string) (FederationIdentity, error) {
	var out FederationIdentity
	if ctx == nil || config == nil || namespace == "" || !authorization.UUID(installation) {
		return out, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	accounts := api.CoreV1().ServiceAccounts(namespace)
	name := contracts.FederationServiceAccountName(installation)
	a, err := accounts.Create(call, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if a, err = accounts.Get(call, name, meta.GetOptions{}); err == nil && (a.AutomountServiceAccountToken == nil || *a.AutomountServiceAccountToken || a.DeletionTimestamp != nil) {
			return out, cfg.ErrChanged
		}
	}
	if err != nil || !authorization.UUID(string(a.UID)) {
		return out, cfg.ErrUnavailable
	}
	secrets := api.CoreV1().Secrets(namespace)
	audit := contracts.FederationAuditSecretName(installation)
	s, err := secrets.Create(call, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: audit}, Type: core.SecretTypeOpaque}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if s, err = secrets.Get(call, audit, meta.GetOptions{}); err == nil && (s.Type != core.SecretTypeOpaque || s.DeletionTimestamp != nil || len(s.Data) > 1) {
			return out, cfg.ErrChanged
		}
	}
	if err != nil || !authorization.UUID(string(s.UID)) {
		return out, cfg.ErrUnavailable
	}
	return FederationIdentity{Account: contracts.WorkerObjectReference{Name: name, UID: string(a.UID)}, AuditCredentials: contracts.WorkerObjectReference{Name: audit, UID: string(s.UID)}}, nil
}
