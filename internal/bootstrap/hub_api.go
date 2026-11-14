package bootstrap

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
)

// RunHubAPI starts the private owner subsystem and, with the optional public
// section of its Helm-rendered config (ADR-180), the public browser/MCP/
// download layer. Inputs come from fixed mounts only; no flag or request can
// replace a provider endpoint, credential path or trust source.
func RunHubAPI(ctx context.Context, podUID string) (result error) {
	phase, purpose := startupFiles, "none"
	defer ownerStartupAnnotate(&phase, &purpose, &result)
	logOpeningStats(ctx, "hub kube opening")
	files, err := os.OpenRoot(contracts.OwnerDeploymentRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer files.Close()
	phase = startupInputs
	mode, err := readOwnerInputs(ctx, files)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	// ADR-182: an identity-only installed owner runs the observation runtime;
	// a promoted installed owner (with Native) runs the full composition.
	if mode.config.Observation != nil && mode.config.Native == nil {
		phase = startupObservationRuntime
		var d *OwnerObservationDeployment
		err := waitStartup(ctx, "hub-api", startupLog, func(ctx context.Context) (err error) {
			d, err = newOwnerObservationDeployment(ctx, files, podUID, mode)
			return err
		}, ownerStartupRetryable)
		if err != nil {
			return errors.Join(mounts.ErrUnavailable, err)
		}
		defer d.Close()
		phase = startupObservationListener
		listener, err := (&net.ListenConfig{KeepAlive: -1}).Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(d.Runtime.pool.NativePort)))
		if err != nil {
			return errors.Join(mounts.ErrUnavailable, err)
		}
		defer listener.Close()
		phase = startupRuntimeSupervisor
		return d.Run(listener)
	}

	phase = startupFullDeployment
	var d *OwnerDeployment
	err = waitStartup(ctx, "hub-api", startupLog, func(ctx context.Context) (err error) {
		d, err = newOwnerDeployment(ctx, files, podUID, mode)
		return err
	}, ownerStartupRetryable)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer d.Close()
	phase = startupFullListener
	stopReadiness, err := serveReadiness(ctx, d.Runtime.Ready)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer stopReadiness()
	listener, err := (&net.ListenConfig{KeepAlive: -1}).Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(d.Runtime.pool.Port)))
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer listener.Close()
	if d.Runtime.pool.NativePort != 0 {
		phase = startupNativeListener
		nativeListener, err := (&net.ListenConfig{KeepAlive: -1}).Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(d.Runtime.pool.NativePort)))
		if err != nil {
			return errors.Join(mounts.ErrUnavailable, err)
		}
		defer nativeListener.Close()
		listeners := []net.Listener{nativeListener}
		if d.Runtime.operation != nil {
			// ADR-197: the v2 operation server's own port.
			phase = startupNativeListener
			operationListener, err := (&net.ListenConfig{KeepAlive: -1}).Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(d.Runtime.pool.OperationPort)))
			if err != nil {
				return errors.Join(mounts.ErrUnavailable, err)
			}
			defer operationListener.Close()
			listeners = append(listeners, operationListener)
		}
		if p := mode.config.Public; p != nil && d.publicHandler != nil {
			// ADR-180: the public HTTPS layer shares the deployment's lifetime.
			publicListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(p.Port)))
			if err != nil {
				return errors.Join(mounts.ErrUnavailable, err)
			}
			defer publicListener.Close()
			public := make(chan error, 1)
			go func() { public <- d.RunPublic(publicListener) }()
			phase = startupFullRuntime
			err = d.Run(listener, listeners...)
			return errors.Join(err, <-public)
		}
		phase = startupFullRuntime
		return d.Run(listener, listeners...)
	}
	phase = startupFullRuntime
	return d.Run(listener)
}

// ownerStartupRetryable retries, in-process, a startup whose accepted owner
// configuration is not current yet: the hub-worker renews its SQL recovery
// and observation intervals, and during an upgrade the new hub-worker waits
// for its scheduling Lease while those intervals lapse. Other failures keep
// exiting, as before.
func ownerStartupRetryable(err error) bool {
	var read *postgres.OwnerConfigurationReadFailure
	return errors.As(err, &read) && startupRetryable(err)
}
