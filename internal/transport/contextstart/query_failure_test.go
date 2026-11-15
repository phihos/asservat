package contextstart

import "asservat.local/asservat/internal/domain/targets"

func queryFailureError(label string) error {
	for _, f := range queryFailures {
		if f.label == label {
			return f.err
		}
	}
	return targets.ErrUnavailable
}
