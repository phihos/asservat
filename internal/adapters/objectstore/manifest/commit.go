package manifest

import (
	"asservat.local/asservat/internal/domain/artifact"
	"encoding/json"
)

type keyDTO struct {
	Reference  string `json:"reference"`
	Ciphertext string `json:"ciphertext"`
}
type manifestReceiptDTO struct {
	Identity         identityDTO `json:"identity"`
	CiphertextBytes  int64       `json:"ciphertextBytes"`
	CiphertextSHA256 string      `json:"ciphertextSHA256"`
	Key              keyDTO      `json:"key"`
}
type commitDTO struct {
	Format        string             `json:"format"`
	StorageFormat string             `json:"storageFormat"`
	ClusterID     string             `json:"clusterID"`
	ArtifactID    string             `json:"artifactID"`
	AttemptID     string             `json:"attemptID"`
	Manifest      manifestReceiptDTO `json:"manifest"`
}

func (v *Validator) MarshalCommit(loc artifact.Location, m artifact.CopyReceipt, k artifact.SealedKey) ([]byte, error) {
	if loc.Validate() != nil {
		return nil, artifact.ErrInvalid
	}
	b, err := json.Marshal(commitDTO{"artifact-commit/v1", artifact.StorageFormat, loc.ClusterID, loc.ArtifactID, loc.AttemptID, manifestReceiptDTO{identity(m), m.Bytes, hash(m.SHA256), keyDTO{k.Reference, k.Ciphertext}}})
	if err != nil {
		return nil, artifact.ErrInvalid
	}
	if err = validate(v.commit, b, 32<<10); err != nil {
		return nil, err
	}
	return b, nil
}

func (v *Validator) ParseCommit(b []byte, loc artifact.Location, m artifact.CopyReceipt) (artifact.SealedKey, error) {
	var zero artifact.SealedKey
	if loc.Validate() != nil {
		return zero, artifact.ErrInvalid
	}
	if err := validate(v.commit, b, 32<<10); err != nil {
		return zero, err
	}
	var d commitDTO
	if err := decode(b, &d); err != nil {
		return zero, err
	}
	version := ""
	if d.Manifest.Identity.VersionID != nil {
		version = *d.Manifest.Identity.VersionID
	}
	if d.ClusterID != loc.ClusterID || d.ArtifactID != loc.ArtifactID || d.AttemptID != loc.AttemptID || d.Manifest.Identity.ETag != m.ETag || version != m.VersionID || d.Manifest.CiphertextBytes != m.Bytes || d.Manifest.CiphertextSHA256 != hash(m.SHA256) {
		return zero, artifact.ErrIntegrity
	}
	return artifact.SealedKey{Reference: d.Manifest.Key.Reference, Ciphertext: d.Manifest.Key.Ciphertext}, nil
}
