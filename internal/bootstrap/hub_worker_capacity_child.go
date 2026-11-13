package bootstrap

import "context"

// runCapacity is a placeholder until the Helm-native capacity composition lands: it
// waits for the Lease to end. The config's capacity section enables it.
func (w *hubWorker) runCapacity(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
