//go:build !gadget || !linux

package gadget

import "context"

func traceArguments(context.Context, ArgumentRequest, func([]byte), func(InputNotice)) (ArgumentStats, error) {
	return ArgumentStats{}, ErrEngineUnavailable
}
