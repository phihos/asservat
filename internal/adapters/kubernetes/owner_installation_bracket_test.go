package kubernetes

import (
	"context"
	"testing"
	"time"
)

func withTimeout(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
