package framed

import (
	"bytes"
	"encoding/json"

	"asservat.local/asservat/internal/domain/artifact"
)

// Check required fields as well as typed decoding: encoding/json alone accepts
// missing/null scalar fields as zero, which is not the persistent wire contract.
func fields(b []byte, names ...string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil || len(m) != len(names) {
		return nil, artifact.ErrInvalid
	}
	for _, name := range names {
		v, ok := m[name]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, artifact.ErrInvalid
		}
	}
	return m, nil
}

func layoutFields(b []byte) error {
	m, err := fields(b, "format", "binding", "nativeBytes", "dataBytes", "indexBytes", "nativeSHA256", "dataSHA256", "indexSHA256", "dataKey", "indexKey", "pages")
	if err != nil {
		return err
	}
	if _, err := fields(m["binding"], "clusterID", "artifactID", "attemptID", "mediaType"); err != nil {
		return err
	}
	for _, key := range []string{"dataKey", "indexKey"} {
		if _, err := fields(m[key], "reference", "ciphertext"); err != nil {
			return err
		}
	}
	var pages []json.RawMessage
	if json.Unmarshal(m["pages"], &pages) != nil || len(pages) < 1 || len(pages) > artifact.MaxPages {
		return artifact.ErrInvalid
	}
	for _, p := range pages {
		if _, err := fields(p, "number", "firstFrame", "frameCount", "nativeOffset", "nativeBytes", "dataOffset", "dataBytes", "indexOffset", "indexBytes", "indexSHA256"); err != nil {
			return err
		}
	}
	return nil
}

func pageFields(b []byte) error {
	m, err := fields(b, "format", "number", "frames")
	if err != nil {
		return err
	}
	var frames []json.RawMessage
	if json.Unmarshal(m["frames"], &frames) != nil || len(frames) < 1 || len(frames) > artifact.FramesPerPage {
		return artifact.ErrInvalid
	}
	for _, f := range frames {
		if _, err := fields(f, "sequence", "nativeOffset", "nativeBytes", "dataOffset", "dataBytes", "codec", "nativeSHA256", "dataSHA256"); err != nil {
			return err
		}
	}
	return nil
}
