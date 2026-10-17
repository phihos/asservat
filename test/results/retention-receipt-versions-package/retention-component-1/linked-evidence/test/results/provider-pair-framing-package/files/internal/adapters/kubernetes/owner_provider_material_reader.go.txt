package kubernetes

import (
	"bytes"
	"context"
	"encoding/hex"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

// MatchesProviderInput is a constructor binding check only. It provides no
// observation or authority and cannot replace Verify's native proof.
func (s *InstalledOwnerIdentityReader) MatchesProviderInput(in contracts.OwnerDeployment) bool {
	return s != nil && in.ProviderAuthentication != nil && s.activation.Input.OwnerLayout == contracts.OwnerProviderInstalledLayout && equalJSON(in, s.input)
}

// ReadProviderAuditCredential compares the currently projected bytes with the
// exact original protected mutable Secret. Rotation may replace its content,
// never its name/UID or one-key shape. Mount metadata supplies no authority.
// The caller retains the returned original end through its storage operation.
func (s *InstalledOwnerIdentityReader) ReadProviderAuditCredential(ctx context.Context, manifest contracts.OwnerIdentityCredentialManifest, mounted map[string][]byte, credential []byte) (contracts.OwnerStorageCredential, time.Time, error) {
	var zero contracts.OwnerStorageCredential
	if s == nil || ctx == nil || ctx.Err() != nil || !s.MatchesProviderInput(s.input) || !ownerProviderAuditMaterial(credential) {
		return zero, time.Time{}, cfg.ErrInvalid
	}
	until, err := s.Verify(ctx, manifest, mounted)
	if err != nil {
		return zero, time.Time{}, err
	}
	call, end := context.WithDeadline(ctx, until)
	defer end()
	p := s.input.ProviderAuthentication
	var object core.Secret
	if err = s.get(call, "/api/v1/namespaces/"+s.input.Namespace.Name+"/secrets/"+p.AuditCredentials.Name, &object); err != nil {
		return zero, time.Time{}, err
	}
	defer clearRuntimeProjection(object.Data)
	if !initialProviderSecretIdentity(object, s.input.Namespace.Name, p.AuditCredentials, contracts.OwnerProviderAuditCredentialFile) || len(object.Data) != 1 || !bytes.Equal(object.Data[contracts.OwnerProviderAuditCredentialFile], credential) {
		return zero, time.Time{}, cfg.ErrChanged
	}
	guard, observed, err := s.protection.Current(call)
	until = identity.Earlier(until, observed)
	if err != nil || s.input.Observation == nil || hex.EncodeToString(guard[:]) != s.input.Observation.ProtectionDigest || initialHandoverDeadline(call, s.client.now, until) != nil {
		return zero, time.Time{}, cfg.ErrUnavailable
	}
	out, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(credential))
	if err != nil {
		return zero, time.Time{}, cfg.ErrChanged
	}
	return out, until, nil
}
