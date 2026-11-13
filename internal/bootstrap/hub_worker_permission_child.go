package bootstrap

import "context"

// runPermission is a placeholder until the Helm-native permission composition lands: it
// waits for the Lease to end. The config's permission section enables it.
func (w *hubWorker) runPermission(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
