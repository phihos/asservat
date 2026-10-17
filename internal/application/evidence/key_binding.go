package evidence

import (
	"encoding/json"
	"encoding/json/jsontext"

	"asservat.local/asservat/internal/domain/artifact"
)

// ArtifactKeyBinding is the existing framed/v1 key envelope binding. It lets
// an authority owner derive the exact three allowed bindings from trusted
// artifact identity without importing a storage adapter or parsing evidence.
func ArtifactKeyBinding(b artifact.Binding, role string) ([]byte, error) {
	if b.Validate() != nil || (role != "data-key" && role != "index-key" && role != "manifest-key") {
		return nil, artifact.ErrInvalid
	}
	if role == "manifest-key" {
		b.MediaType = "application/vnd.asservat.manifest+json"
	}
	v, err := json.Marshal(struct {
		Format   string `json:"format"`
		Schema   string `json:"schema"`
		Cluster  string `json:"clusterID"`
		Artifact string `json:"artifactID"`
		Attempt  string `json:"attemptID"`
		Media    string `json:"mediaType"`
		Role     string `json:"role"`
		Sequence int    `json:"sequence"`
		Offset   int    `json:"nativeOffset"`
		Size     int    `json:"nativeBytes"`
		Codec    string `json:"codec"`
	}{artifact.StorageFormat, "artifact/v1", b.ClusterID, b.ArtifactID, b.AttemptID, b.MediaType, role, 0, 0, 0, "none"})
	c := jsontext.Value(v)
	if err != nil || c.Canonicalize() != nil {
		return nil, artifact.ErrInvalid
	}
	return c, nil
}
