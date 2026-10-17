package postgres

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Encode returns secrets for protected immutable storage before provisioning.
// Keeping those exact bytes enables uncertain-result replay without issuing
// fresh passwords or extending the original validity. Clear caller-owned bytes.
func EncodeInitialSQLCredentials(p InitialSQLCredentials, plan artifact.Digest) ([]byte, error) {
	if !p.valid() || plan == (artifact.Digest{}) {
		return nil, value.ErrInvalid
	}
	login := func(l InitialSQLLogin) contracts.OwnerSQLCredential {
		return contracts.OwnerSQLCredential{Username: l.Username, Password: l.Password}
	}
	w := contracts.InitialSQLCredentialState{Format: contracts.InitialSQLCredentialsFormat, InstallationID: p.InstallationID, PlanDigest: hex.EncodeToString(plan[:]), NotBefore: p.NotBefore, NotAfter: p.NotAfter, Preparation: login(p.Preparation), Audit: login(p.Audit), Activation: login(p.Activation)}
	return json.Marshal(w)
}

// Decoding checks immutable scope but deliberately not current expiry: retiring
// an abandoned attempt must remain possible after its password expires.
func DecodeInitialSQLCredentials(raw []byte, installation string, plan artifact.Digest) (InitialSQLCredentials, error) {
	w, err := contracts.DecodeInitialSQLCredentialState(bytes.NewReader(raw))
	if err != nil || w.Format != contracts.InitialSQLCredentialsFormat || w.InstallationID != installation || plan == (artifact.Digest{}) || w.PlanDigest != hex.EncodeToString(plan[:]) {
		return InitialSQLCredentials{}, value.ErrInvalid
	}
	login := func(l contracts.OwnerSQLCredential) InitialSQLLogin { return InitialSQLLogin{l.Username, l.Password} }
	p := InitialSQLCredentials{InstallationID: w.InstallationID, NotBefore: w.NotBefore, NotAfter: w.NotAfter, Preparation: login(w.Preparation), Audit: login(w.Audit), Activation: login(w.Activation)}
	if !p.valid() {
		return InitialSQLCredentials{}, value.ErrInvalid
	}
	return p, nil
}
