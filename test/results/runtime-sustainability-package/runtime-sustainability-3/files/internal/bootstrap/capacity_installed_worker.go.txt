package bootstrap

import (
	"context"
	"os"
	"reflect"
	"strings"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// This private selection is made only by the named installed constructor after
// a positive current public-journal/Secret observation. It is not an effect
// permit and supplies no caller-selected provider or transport factory.
type installedCapacityWorkerInputs struct {
	files    *os.Root
	worker   contracts.HubWorkerDeployment
	expected contracts.CapacityRuntimeProjectionClaim
	until    time.Time
	startup  context.Context
}

func NewInstalledCapacityWorkerDeployment(ctx context.Context, files, workerFiles *os.Root, worker contracts.HubWorkerDeployment, reader *kube.InstalledWorkerProjectionReader, expected contracts.CapacityRuntimeProjectionClaim) (*CapacityWorkerDeployment, error) {
	if ctx == nil || ctx.Err() != nil || files == nil || workerFiles == nil || reader == nil || expected.Receipt == nil || !kube.HubWorkerActivationBound(worker) {
		return nil, mounts.ErrUnavailable
	}
	observed, ready, until, err := reader.ReadCapacity(ctx)
	if err != nil || !ready || !reflect.DeepEqual(observed, expected) || !time.Now().Before(until) {
		return nil, mounts.ErrUnavailable
	}
	selected := &installedCapacityWorkerInputs{files: workerFiles, worker: worker, expected: observed, until: until}
	return newCapacityWorkerDeployment(ctx, files, selected)
}

func (s *installedCapacityWorkerInputs) matches(c contracts.CapacityDeployment, m contracts.CapacityCredentialManifest) bool {
	if s == nil || !time.Now().Before(s.until) || !capacityProjectionMatches(c, m, s.expected, s.worker) || c.LocalOwner == nil {
		return false
	}
	if _, err := kube.CapacityLocalOwnerBinding(c, m); err != nil {
		return false
	}
	w := s.worker
	o := c.LocalOwner.Deployment
	if w.Activation == nil || c.Control.ProbeAccount != w.Activation.ServiceAccount || !reflect.DeepEqual(c.Control.Kubernetes, w.Kubernetes) || !reflect.DeepEqual(o.Kubernetes, w.Kubernetes) ||
		!reflect.DeepEqual(o.WorkloadGuard, w.Activation.WorkloadGuard) || !reflect.DeepEqual(o.ConfigurationProbes, w.Activation.ConfigurationProbes) ||
		!reflect.DeepEqual(o.SchedulingLeases, w.Activation.SchedulingLeases) || !reflect.DeepEqual(o.InitialHistoryProbe, w.Activation.InitialHistoryProbe) {
		return false
	}
	if o.CapacityProbe == nil || o.CapacityProbe.ServiceAccount != w.Activation.ServiceAccount || !reflect.DeepEqual(o.CapacityProbe, w.Activation.CapacityProbe) {
		return false
	}
	prefix := "asservat-" + strings.ReplaceAll(c.InstallationID, "-", "")
	if c.Control.Guard.Name != prefix+"-capacity-guard" || c.Processing.Guard.Name != prefix+"-processing-guard" || c.Processing.Source.Name != prefix+"-processing-source" {
		return false
	}
	// The source-specific denial still comes from the independent processing
	// policy; the original namespace guard only permits this exact dry-run probe.
	found := false
	for _, p := range o.ConfigurationProbes {
		if p.ConfigMap == c.Processing.Source.Name && p.ServiceAccount == c.Control.ProbeAccount.Name {
			found = true
		}
	}
	return found
}

func (s *installedCapacityWorkerInputs) localInputs(ctx context.Context, c contracts.CapacityDeployment, m contracts.CapacityCredentialManifest) (*providerInputs, error) {
	if !s.matches(c, m) {
		return nil, mounts.ErrUnavailable
	}
	in, current, err := readHubWorkerInputs(ctx, s.files)
	if err != nil || !reflect.DeepEqual(current, s.worker) || ctx.Err() != nil || !time.Now().Before(s.until) {
		if in != nil {
			in.closeHTTP()
		}
		return nil, mounts.ErrUnavailable
	}
	return in, nil
}
