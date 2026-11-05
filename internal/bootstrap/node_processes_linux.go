//go:build linux

package bootstrap

import (
	"context"
	"os"

	"asservat.local/asservat/internal/adapters/cri"
	kernel "asservat.local/asservat/internal/adapters/linux"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

func nodeProcessAcquirer(selected string, f collector.Facts) func(context.Context, collector.ProcessCapture) (artifact.ProcessInventory, error) {
	if selected != "containerd" || f.CgroupV2 != collector.Supported || f.HostProcesses != collector.Supported {
		return nil
	}
	info, e := os.Stat("/run/containerd/containerd.sock")
	if e != nil || info.Mode()&os.ModeSocket == 0 {
		return nil
	}
	if _, e = os.Stat("/sys/fs/cgroup/cgroup.controllers"); e != nil {
		return nil
	}
	return func(ctx context.Context, p collector.ProcessCapture) (artifact.ProcessInventory, error) {
		var zero artifact.ProcessInventory
		if ctx == nil || ctx.Err() != nil || !p.Valid() {
			return zero, kernel.ErrProcessUnavailable
		}
		client, e := cri.NewProcesses("containerd", "/run/containerd/containerd.sock")
		if e != nil {
			return zero, e
		}
		defer client.Close()
		return kernel.NewProcessSnapshots(client).Capture(ctx, p.Request)
	}
}
