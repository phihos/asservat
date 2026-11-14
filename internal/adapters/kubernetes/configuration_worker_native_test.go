package kubernetes

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	apps "k8s.io/api/apps/v1"
)

func TestConfigurationRoleStatusUpdatesKeepOriginalSourceAndRecheck(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	var reads atomic.Int32
	f.deploymentEdit = func(d *apps.Deployment) {
		if d.Name == f.source.input.Deployment.Name {
			n := reads.Add(1)
			d.ResourceVersion = strconv.Itoa(int(n))
			d.Status.ReadyReplicas = n % 2
		}
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	initial, err := f.source.readConfigurationRoleSource(ctx)
	if err != nil {
		t.Fatal("ordinary source rejected status-only first/final bracket", err)
	}
	current, err := f.source.recheckConfigurationRoleSource(ctx, initial)
	if err != nil || current.observation != initial.observation || current.deployment == nil || current.deployment.ResourceVersion != "3" {
		t.Fatal("ordinary post-lock recheck lost source/deadline/latest snapshot", err)
	}
	if f.secretWrites.Load() != 0 || f.probes.Load() != 2 {
		t.Fatal("ordinary status update recheck added a write or changed probe count")
	}
}

func TestConfigurationWorkerNativeConstructorKeepsExactClientsAndPins(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	s := f.source
	if got, err := NewConfigurationRoleSource(s.client, s.protection, s.fleet, s.owner, s.input); err != nil || got.client != s.client || got.protection != s.protection || got.fleet != s.fleet || got.owner != s.owner {
		t.Fatal("constructor replaced an original configured client", err)
	}
	for _, mode := range []string{"client", "namespace", "fleet-client", "owner-client", "fleet-pin", "owner-pin", "guard-client", "guard-namespace"} {
		t.Run(mode, func(t *testing.T) {
			client, protection, fleetSource, owner := s.client, *s.protection, *s.fleet, *s.owner
			settings := *s.fleet.settings
			fleetSource.settings = &settings
			input := s.input
			switch mode {
			case "client":
				copy := *client
				client = &copy
			case "namespace":
				input.Namespace.UID = ownerID(15000)
			case "fleet-client":
				copy := *client
				settings.client = &copy
			case "owner-client":
				copy := *client
				owner.client = &copy
			case "fleet-pin":
				input.FleetSource.UID = ownerID(15000)
			case "owner-pin":
				input.OwnerSource.UID = ownerID(15000)
			case "guard-client":
				copy := *client
				protection.observer = &copy
			case "guard-namespace":
				protection.plan.ControlNamespace.UID = ownerID(15000)
			}
			if _, err := NewConfigurationRoleSource(client, &protection, &fleetSource, &owner, input); err == nil {
				t.Fatal("constructor adopted a substituted client or input pin")
			}
		})
	}
	if f.requests.Load() != 0 {
		t.Fatal("pure constructor claimed current readiness through network I/O")
	}
}
