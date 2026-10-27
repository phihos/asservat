//go:build !linux

package linux

import (
	"errors"

	"asservat.local/asservat/internal/domain/collector"
)

func statfsType(string) (int64, error) { return 0, errors.ErrUnsupported }

// ProbeBPF reports nothing on other operating systems.
func ProbeBPF() (bpf, tc, tcx collector.Support) {
	return collector.Unsupported, collector.Unsupported, collector.Unsupported
}
