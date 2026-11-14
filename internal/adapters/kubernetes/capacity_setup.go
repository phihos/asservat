package kubernetes

import (
	"encoding/hex"
)

func capacitySetupDigest(v string) bool {
	b, err := hex.DecodeString(v)
	var nonzero byte
	for _, x := range b {
		nonzero |= x
	}
	return err == nil && len(b) == 32 && nonzero != 0 && hex.EncodeToString(b) == v
}
