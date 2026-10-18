package providerconfig

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
)

// OwnerPublicReadback is what a promoted owner input pins from the applied
// provider (ADR-194 step 6): the work-signing key's latest version and public
// key, and the worker PKI issuer as the worker trust root.
type OwnerPublicReadback struct {
	Signing     contracts.OwnerPublicSigning
	WorkerRoots [][]byte
	Until       time.Time
}

// VerifyOwnerPublic reads the promoted owner's applied public setup back
// through the inspection token. in.Public carries the derived names. Both
// Transit keys must have the exact type and non-exportable settings, each
// role and policy must equal the recipe, and the worker PKI role must be
// exact. It confers no authority to use any key or role.
func (r *SetupReader) VerifyOwnerPublic(ctx context.Context, in contracts.OwnerDeployment, profile contracts.OwnerProviderAuthentication) (OwnerPublicReadback, error) {
	var out OwnerPublicReadback
	if in.Public == nil {
		return out, ErrSetupUnavailable
	}
	_, paths, _, err := ownerPublicSetup(in, profile, time.Now())
	if err != nil {
		return out, err
	}
	roles, _, err := OwnerPublicProviderRecipeFor(in, profile, time.Now())
	if err != nil {
		return out, ErrSetupUnavailable
	}
	pkiRole, err := ownerWorkerPKIRole(in.InstallationID)
	if err != nil {
		return out, err
	}
	p, k := in.Public, in.KeyService
	o, err := r.begin(ctx, contracts.OwnerProviderEndpoint{Endpoint: k.Endpoint, Roots: k.Roots}, paths)
	if err != nil {
		return out, err
	}
	defer o.finish()
	signing := contracts.OwnerPublicSigning{Mount: p.WorkSigning.Mount, Name: p.WorkSigning.Name}
	var issuerUntil time.Time
	checks := []setupReadCheck{
		{"sys/mounts/" + p.SessionTransit.Mount, "public transit engine", verifyTransitMount},
		{p.SessionTransit.Mount + "/keys/" + p.SessionTransit.Key, "browser session key", func(d map[string]json.RawMessage) error { return verifyTransitKey(d, p.SessionTransit.Key) }},
		{p.WorkSigning.Mount + "/keys/" + p.WorkSigning.Name, "work-signing key", func(d map[string]json.RawMessage) error {
			v, key, e := verifySigningKey(d, p.WorkSigning.Name)
			signing.Version, signing.PublicKey = v, key
			return e
		}},
		{"sys/mounts/" + p.WorkerPKI.Mount, "worker certificate engine", func(d map[string]json.RawMessage) error {
			if !setupIs(d, "type", "pki") {
				return ErrSetupUnavailable
			}
			return nil
		}},
		{p.WorkerPKI.Mount + "/cert/ca", "worker certificate issuer", func(d map[string]json.RawMessage) error {
			der, end, e := setupIssuerRoot(d, time.Now())
			out.WorkerRoots, issuerUntil = [][]byte{der}, end
			return e
		}},
		{p.WorkerPKI.Mount + "/roles/" + p.WorkerPKI.Role, "worker certificate role", func(d map[string]json.RawMessage) error { return verifySetupPKIRole(d, pkiRole) }},
	}
	for _, role := range roles {
		checks = append(checks,
			setupReadCheck{"auth/" + profile.AuthMount + "/role/" + role.Name, "public " + role.Purpose + " role", func(d map[string]json.RawMessage) error { return verifyKubernetesRole(d, role.Role) }},
			setupReadCheck{"sys/policies/acl/" + role.Name, "public " + role.Purpose + " policy", func(d map[string]json.RawMessage) error { return verifyACL(d, role.Name, role.Policy) }})
	}
	for _, check := range checks {
		data, e := o.get(check.path)
		if e != nil || check.verify(data) != nil {
			return OwnerPublicReadback{}, setupComponentError(check.component)
		}
	}
	if !o.valid() {
		return OwnerPublicReadback{}, ErrSetupUnavailable
	}
	signing.KeyID = signing.Name + "-v" + strconv.Itoa(signing.Version)
	out.Signing, out.Until = signing, identity.Earlier(o.until, issuerUntil)
	return out, nil
}

// verifySigningKey requires a non-exportable, non-deletable Ed25519 key and
// returns its latest version and that version's public key.
func verifySigningKey(data map[string]json.RawMessage, name string) (int, []byte, error) {
	if !setupIs(data, "name", name) || !setupIs(data, "type", "ed25519") || !setupIs(data, "derived", false) || !setupIs(data, "exportable", false) || !setupIs(data, "allow_plaintext_backup", false) || !setupIs(data, "deletion_allowed", false) || !setupIs(data, "supports_signing", true) {
		return 0, nil, ErrSetupUnavailable
	}
	latest, ok := setupValue[int64](data, "latest_version")
	var keys map[string]struct {
		PublicKey string `json:"public_key"`
	}
	if !ok || latest < 1 || latest > 1<<20 || json.Unmarshal(data["keys"], &keys) != nil {
		return 0, nil, ErrSetupUnavailable
	}
	key, err := base64.StdEncoding.DecodeString(keys[strconv.FormatInt(latest, 10)].PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return 0, nil, ErrSetupUnavailable
	}
	return int(latest), key, nil
}

// verifySigningKeyVersions is verifySigningKey that also returns the public
// key of every version Transit lists (at most 32, the verifiers' bound), so
// records signed before a rotation still verify against pinned keys.
func verifySigningKeyVersions(data map[string]json.RawMessage, name string) (int, map[int]ed25519.PublicKey, error) {
	latest, _, err := verifySigningKey(data, name)
	var keys map[string]struct {
		PublicKey string `json:"public_key"`
	}
	if err != nil || json.Unmarshal(data["keys"], &keys) != nil || len(keys) < 1 || len(keys) > 32 {
		return 0, nil, ErrSetupUnavailable
	}
	out := make(map[int]ed25519.PublicKey, len(keys))
	for v, k := range keys {
		version, e := strconv.Atoi(v)
		key, d := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		if e != nil || strconv.Itoa(version) != v || version < 1 || version > latest || d != nil || len(key) != ed25519.PublicKeySize {
			return 0, nil, ErrSetupUnavailable
		}
		out[version] = key
	}
	return latest, out, nil
}

// setupIssuerRoot accepts exactly one current CA certificate as the issuer's
// trust root and returns its DER and expiry.
func setupIssuerRoot(data map[string]json.RawMessage, now time.Time) ([]byte, time.Time, error) {
	value, ok := setupValue[string](data, "certificate")
	if !ok {
		return nil, time.Time{}, ErrSetupUnavailable
	}
	certificates, err := setupPEMCertificates(value)
	if err != nil || len(certificates) != 1 {
		return nil, time.Time{}, ErrSetupUnavailable
	}
	cert, err := x509.ParseCertificate(certificates[0])
	if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, time.Time{}, ErrSetupUnavailable
	}
	_, end, err := mtls.OwnerTrustRoots(certificates, now)
	if err != nil {
		return nil, time.Time{}, ErrSetupUnavailable
	}
	return certificates[0], end, nil
}
