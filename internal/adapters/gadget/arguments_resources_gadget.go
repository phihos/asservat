//go:build gadget && linux

package gadget

import (
	"github.com/cilium/ebpf"
	"os"
)

// ArgumentWorkingBytes is read before node admission; it creates no kernel maps.
func ArgumentWorkingBytes(maxTracked int) (int64, error) {
	n, err := ebpf.PossibleCPU()
	if err != nil {
		return 0, ErrEngineUnavailable
	}
	return ArgumentWorkingSet(n, os.Getpagesize(), maxTracked)
}
