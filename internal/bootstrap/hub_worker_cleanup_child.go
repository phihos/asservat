package bootstrap

import "context"

// runCleanup is a placeholder until the Helm-native cleanup composition lands: it
// waits for the Lease to end. The config's cleanup section enables it.
func (w *hubWorker) runCleanup(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
