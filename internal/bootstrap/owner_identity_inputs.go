package bootstrap

import (
	"bytes"
	"context"
	"os"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// Read the complete fixed provider bundle for independent native projection
// comparison, not for authority. No optional backend/public/root credentials
// are opened. The caller clears every buffer after original verification.
func readOwnerIdentityProviders(ctx context.Context, files *os.Root) (map[string][]byte, contracts.OwnerIdentityCredentialManifest, error) {
	return readFixedOwnerIdentityProviders(ctx, files, append(contracts.OwnerIdentityProjectionFiles(), "audit-storage.json", "audit-wrap.token", "audit-unwrap.token", "owner-server-sign.token", "owner-client-sign.token"))
}

func readSelectedOwnerIdentityProviders(ctx context.Context, files *os.Root, in contracts.OwnerDeployment) (map[string][]byte, contracts.OwnerIdentityCredentialManifest, error) {
	if in.ProviderAuthentication == nil {
		return readOwnerIdentityProviders(ctx, files)
	}
	if in.Observation == nil || in.Observation.Activation == nil || in.Observation.Activation.Input.OwnerLayout != contracts.OwnerProviderInstalledLayout {
		return nil, contracts.OwnerIdentityCredentialManifest{}, mounts.ErrUnavailable
	}
	// Legacy material must not be silently ignored by a selected v2 profile.
	for _, name := range []string{"audit-storage.json", "audit-wrap.token", "audit-unwrap.token", "owner-server-sign.token", "owner-client-sign.token"} {
		if _, err := files.Lstat(name); !os.IsNotExist(err) {
			return nil, contracts.OwnerIdentityCredentialManifest{}, mounts.ErrUnavailable
		}
	}
	return readFixedOwnerIdentityProviders(ctx, files, contracts.OwnerIdentityProjectionFiles())
}

func readFixedOwnerIdentityProviders(ctx context.Context, files *os.Root, keys []string) (map[string][]byte, contracts.OwnerIdentityCredentialManifest, error) {
	var zero contracts.OwnerIdentityCredentialManifest
	out := map[string][]byte{}
	complete := false
	defer func() {
		if !complete {
			for _, b := range out {
				clear(b)
			}
		}
	}()
	for _, key := range keys {
		b, e := mounts.Read(ctx, files, key, contracts.OwnerIdentityRoleMaxBytes)
		if e != nil || len(b) == 0 {
			clear(b)
			return nil, zero, mounts.ErrUnavailable
		}
		out[key] = b
	}
	manifest, e := contracts.DecodeOwnerIdentityCredentialManifest(bytes.NewReader(out[contracts.OwnerIdentityRoleManifestFile]))
	if e != nil || ctx.Err() != nil {
		return nil, zero, mounts.ErrUnavailable
	}
	complete = true
	return out, manifest, nil
}
