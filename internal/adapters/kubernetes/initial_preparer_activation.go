package kubernetes

import (
	"encoding/hex"
)

func preparationDigestValid(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == v
}
