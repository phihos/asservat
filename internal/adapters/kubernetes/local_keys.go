package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"time"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type LocalKeySource struct {
	client    *PermissionClient
	name, uid string
	scope     value.KeyScope
}

var _ app.KeyMaterialReader = (*LocalKeySource)(nil)

func NewLocalKeySource(c *PermissionClient, name, uid string, scope value.KeyScope) (*LocalKeySource, error) {
	if c == nil || !installationRefValid(name, uid) || !scope.Valid() {
		return nil, app.ErrKeyUnavailable
	}
	return &LocalKeySource{c, name, uid, scope}, nil
}
func (s *LocalKeySource) configuration(ctx context.Context) (contracts.LocalKeyConfiguration, artifact.Digest, error) {
	var w contracts.LocalKeyConfiguration
	data, _, err := s.client.installationConfig(ctx, s.name, s.uid)
	if err != nil || len(data) != 1 || len(data["keys.json"]) == 0 || len(data["keys.json"]) > 4096 {
		return w, artifact.Digest{}, app.ErrKeyUnavailable
	}
	b := []byte(data["keys.json"])
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&w) != nil {
		return w, artifact.Digest{}, app.ErrKeyUnavailable
	}
	expected, e := json.Marshal(w)
	a, z := jsontext.Value(b), jsontext.Value(expected)
	if e != nil || a.Canonicalize() != nil || z.Canonicalize() != nil || !bytes.Equal(a, z) || w.Format != "asservat-local-key-configuration/v1" || w.InstallationID != s.scope.InstallationID || w.Purpose != s.scope.Purpose || w.KeyID != s.scope.KeyID || !value.UUID(w.RecoveryEpoch) || w.Revision < 1 || w.Revision > 2147483647 || !installationRefValid(w.Secret.Name, w.Secret.UID) {
		return w, artifact.Digest{}, app.ErrKeyUnavailable
	}
	hash, e := hex.DecodeString(w.Secret.SHA256)
	if e != nil || len(hash) != 32 || hex.EncodeToString(hash) != w.Secret.SHA256 || bytes.Equal(hash, make([]byte, 32)) || (w.Purpose == "policy-submission" && len(w.SigningPublicKey) != 32) || (w.Purpose != "policy-submission" && len(w.SigningPublicKey) != 0) {
		return w, artifact.Digest{}, app.ErrKeyUnavailable
	}
	return w, artifact.Digest(sha256.Sum256(a)), nil
}
func (s *LocalKeySource) ReadKeyMaterial(ctx context.Context) (app.KeyMaterial, error) {
	var zero app.KeyMaterial
	if s == nil || ctx == nil {
		return zero, app.ErrKeyUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := s.client.now()
	w, digest, err := s.configuration(ctx)
	if err != nil {
		return zero, app.ErrKeyUnavailable
	}
	raw, err := s.client.raw(ctx, "/api/v1/namespaces/"+s.client.control.Name+"/secrets/"+w.Secret.Name, nil)
	defer clear(raw)
	if err != nil || len(raw) > 48<<10 {
		return zero, app.ErrKeyUnavailable
	}
	var object struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Type       string `json:"type"`
		Immutable  bool   `json:"immutable"`
		Metadata   struct {
			Name, Namespace, UID, ResourceVersion string
			DeletionTimestamp                     *string
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if json.Unmarshal(raw, &object) != nil || object.APIVersion != "v1" || object.Kind != "Secret" || object.Type != "Opaque" || !object.Immutable || object.Metadata.Name != w.Secret.Name || object.Metadata.Namespace != s.client.control.Name || object.Metadata.UID != w.Secret.UID || !identity.Text(object.Metadata.ResourceVersion, 128) || object.Metadata.DeletionTimestamp != nil || len(object.Data) != 1 {
		return zero, app.ErrKeyUnavailable
	}
	encoded := object.Data["keys.json"]
	if len(encoded) < 1 || len(encoded) > base64.StdEncoding.EncodedLen(16<<10) {
		return zero, app.ErrKeyUnavailable
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(encoded)
	success := false
	defer func() {
		if !success {
			clear(payload)
		}
	}()
	sum := sha256.Sum256(payload)
	if err != nil || len(payload) == 0 || len(payload) > 16<<10 || base64.StdEncoding.EncodeToString(payload) != encoded || hex.EncodeToString(sum[:]) != w.Secret.SHA256 {
		return zero, app.ErrKeyUnavailable
	}
	_, again, err := s.configuration(ctx)
	if err != nil || again != digest || s.client.current(ctx, started, 5*time.Second) != nil {
		return zero, app.ErrKeyUnavailable
	}
	c := value.LocalKeyConfiguration{Scope: s.scope, ClusterID: s.client.clusterID, NamespaceUID: s.client.control.UID, RecoveryEpoch: w.RecoveryEpoch, Revision: identity.Revision{UID: s.uid, Generation: w.Revision, Digest: digest}, SecretUID: w.Secret.UID, SecretDigest: artifact.Digest(sum), Suspended: w.Suspended, ObservedAt: started, FreshUntil: started.Add(5 * time.Second)}
	success = true
	return app.KeyMaterial{Configuration: c, Payload: payload, SigningPublic: bytes.Clone(w.SigningPublicKey)}, nil
}
