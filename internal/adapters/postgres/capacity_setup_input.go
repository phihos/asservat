package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"io"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

type capacitySetupInput struct {
	value         contracts.CapacityRootSetup
	qualification app.CapacityQualification
	guard         artifact.Digest
	bytes         []byte
	digest        string
}

// Validate every static input before the irreversible root claim. The closed
// qualified C-07 object is decoded separately from its transport RawMessage;
// unknown nested fields and zero/malformed identities never become a hash-only
// promise for later SQL validation.
func decodeCapacitySetupInput(v contracts.CapacityRootSetup, original contracts.PublicRuntimeRoles) (capacitySetupInput, error) {
	var out capacitySetupInput
	if v.Format != contracts.CapacityRootSetupFormat || v.InstallationID != original.InstallationID || v.InitialClaimID != original.InitialClaimID || !authorization.UUID(v.PermissionRootID) || !authorization.UUID(v.RoleRootUID) || !authorization.UUID(v.RoleSetupID) || !authorization.UUID(v.ControlClusterID) || !identity.Text(v.ControlNamespaceUID, 64) || !identity.Text(v.AccountVersion, 64) || len(v.Qualification) < 2 || len(v.Qualification) > 128<<10 {
		return out, cfg.ErrInvalid
	}
	guard, err := hex.DecodeString(v.SourceGuardDigest)
	if err != nil || len(guard) != 32 || hex.EncodeToString(guard) != v.SourceGuardDigest {
		return out, cfg.ErrInvalid
	}
	copy(out.guard[:], guard)
	if out.guard == (artifact.Digest{}) {
		return out, cfg.ErrInvalid
	}
	raw := jsontext.Value(bytes.Clone(v.Qualification))
	if raw.Canonicalize() != nil {
		return out, cfg.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(v.Qualification))
	d.DisallowUnknownFields()
	if d.Decode(&out.qualification) != nil {
		return out, cfg.ErrInvalid
	}
	var extra any
	if d.Decode(&extra) != io.EOF || !out.qualification.Valid() {
		return out, cfg.ErrInvalid
	}
	canonical, err := json.Marshal(out.qualification)
	if err != nil || !capacitySameJSONFields(v.Qualification, canonical) {
		return out, cfg.ErrInvalid
	}
	r := out.qualification.RootBacking
	if r.RootID != v.PermissionRootID || r.InstallationID != v.InstallationID || r.AccountVersion != v.AccountVersion || !app.ValidateRootBackingInput(r) {
		return out, cfg.ErrInvalid
	}
	// Canonical typed JSON fixes the entire input ordering and normalizes the
	// nested measurement before digesting. The public digest includes no password.
	v.Qualification = canonical
	out.value = v
	out.bytes, err = json.Marshal(v)
	if err != nil || len(out.bytes) > contracts.CapacityRootSetupMaxBytes {
		return capacitySetupInput{}, cfg.ErrInvalid
	}
	h := sha256.New()
	_, _ = h.Write([]byte("asservat-capacity-root-setup/json-v1\x00"))
	_, _ = h.Write(out.bytes)
	out.digest = hex.EncodeToString(h.Sum(nil))
	return out, nil
}

// PostgreSQL jsonb text adds separators and normalizes strings. Check its
// actual retained sizes read-only before the irreversible claim; a locally
// valid compact JSON input must not consume setup and then fail a row bound.
func capacitySetupStaticSQL(ctx context.Context, q publicRoleQuery, in capacitySetupInput, roles []capacitySetupRole) error {
	if len(roles) != len(contracts.CapacitySetupRolePurposes()) {
		return cfg.ErrInvalid
	}
	raw, err := json.Marshal(roles)
	if err != nil {
		return cfg.ErrInvalid
	}
	var valid bool
	err = q.QueryRow(ctx, `SELECT public.capacity_qualification_valid($1::jsonb)
 AND octet_length(($1::jsonb)::text) BETWEEN 2 AND 131072
 AND octet_length(($2::jsonb)::text)<=147456
 AND octet_length(($3::jsonb)::text)<=16384`, in.value.Qualification, in.bytes, raw).Scan(&valid)
	if err != nil || ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	if !valid {
		return cfg.ErrInvalid
	}
	return nil
}
