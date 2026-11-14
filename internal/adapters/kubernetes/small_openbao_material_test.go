package kubernetes

import (
	"bytes"
)

func cloneSmallOpenBaoMaterial(m map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range m {
		out[k] = bytes.Clone(v)
	}
	return out
}
