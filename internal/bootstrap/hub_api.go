package bootstrap

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// RunHubAPI starts the private owner subsystem and, only with the installer's
// optional Public section (ADR-180), the public browser/MCP/download layer.
// The installer owns the fixed protected projection; no flag or user request
// can replace a provider endpoint, credential path or startup trust source.
func RunHubAPI(ctx context.Context, podUID string) (result error) {
	phase, purpose := startupFiles, "none"
	defer ownerStartupAnnotate(&phase, &purpose, &result)
	files, err := os.OpenRoot(contracts.OwnerDeploymentRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer files.Close()
	// Select only the explicit original public mode before unrelated credentials
	// or worker/native constructors. The concrete loader independently verifies
	// actual installation receipts and current identity before any SQL authority.
	phase = startupInputs
	mode, err := readOwnerInputs(ctx, files)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	// ADR-182: an identity-only installed owner runs the observation runtime;
	// a promoted installed owner (with Native) runs the full composition.
	if mode.config.Observation != nil && mode.config.Native == nil {
		phase = startupObservationRuntime
		d, err := NewOwnerObservationDeployment(ctx, files, podUID)
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
	d, err := NewOwnerDeployment(ctx, files, podUID)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer d.Close()
	phase = startupFullListener
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
