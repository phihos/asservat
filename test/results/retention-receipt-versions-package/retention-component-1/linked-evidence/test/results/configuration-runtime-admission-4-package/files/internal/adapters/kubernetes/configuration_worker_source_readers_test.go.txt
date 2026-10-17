package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

func TestConfigurationWorkerSourceReadersUseActualEightReadBrackets(t *testing.T) {
	f := newConfigurationProviderRuntimeFixture(t)
	fleet, owner, err := NewConfigurationWorkerSourceReaders(f.reader)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	a, err := fleet.FleetAdministration(t.Context())
	if err != nil || !a.Valid(time.Now()) || a.ObservedAt.Before(started) || !a.FreshUntil.Equal(a.ObservedAt.Add(5*time.Second)) {
		t.Fatal("fleet original source interval", err)
	}
	started = time.Now()
	o, err := owner.ReadOwnerConfiguration(t.Context())
	if err != nil || !o.Valid(time.Now()) || o.ObservedAt.Before(started) || !o.FreshUntil.Equal(o.ObservedAt.Add(5*time.Second)) {
		t.Fatal("owner original source interval", err)
	}
	if f.observer.Load() != 16 || f.probe.Load() != 6 || f.denials[0].Load() != 0 || f.denials[1].Load() != 1 || f.denials[2].Load() != 1 {
		t.Fatal("independent fixed source request graph changed", f.observer.Load(), f.probe.Load())
	}
}

func TestConfigurationWorkerSourceReadersRetainCurrentValuesAndSuspension(t *testing.T) {
	for _, source := range []string{"fleet", "owner"} {
		for _, mode := range []string{"suspended", "changed during final guard", "probe account", "cancelled"} {
			t.Run(source+"/"+mode, func(t *testing.T) {
				f := newConfigurationProviderRuntimeFixture(t)
				fleet, owner, err := NewConfigurationWorkerSourceReaders(f.reader)
				if err != nil {
					t.Fatal(err)
				}
				name, guard := f.input.OwnerSource.Name, f.input.OwnerGuard.Name
				if source == "fleet" {
					name, guard = f.input.FleetSource.Name, f.input.FleetGuard.Name
				}
				mutate := func() {
					f.mu.Lock()
					defer f.mu.Unlock()
					object := f.objects["/api/v1/namespaces/"+f.input.Namespace.Name+"/configmaps/"+name].(*core.ConfigMap)
					if source == "fleet" {
						var value contracts.FleetSettings
						if json.Unmarshal([]byte(object.Data["fleet.json"]), &value) != nil {
							t.Error("synthetic fleet shape")
							return
						}
						value.Suspended = true
						value.Revision++
						raw, _ := json.Marshal(value)
						object.Data["fleet.json"] = string(raw)
					} else {
						var value contracts.OwnerConfiguration
						if json.Unmarshal([]byte(object.Data["owner-pool.json"]), &value) != nil {
							t.Error("synthetic owner shape")
							return
						}
						value.Suspended = true
						value.Revision++
						raw, _ := json.Marshal(value)
						object.Data["owner-pool.json"] = string(raw)
					}
					object.ResourceVersion = "changed"
				}
				call, end := context.WithTimeout(t.Context(), 5*time.Second)
				defer end()
				switch mode {
				case "suspended":
					mutate()
				case "changed during final guard":
					var reads atomic.Int32
					f.setExtra(func(_ http.ResponseWriter, r *http.Request) bool {
						if strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicybindings/"+guard) && reads.Add(1) == 2 {
							mutate()
						}
						return false
					})
				case "probe account":
					f.fault.Store(3)
				case "cancelled":
					end()
				}
				suspended := false
				if source == "fleet" {
					a, e := fleet.FleetAdministration(call)
					err, suspended = e, a.Suspended
				} else {
					o, e := owner.ReadOwnerConfiguration(call)
					err, suspended = e, o.Configuration.Suspended
				}
				if mode == "suspended" {
					if err != nil || !suspended {
						t.Fatal("valid suspension was not returned to SQL observer", err)
					}
				} else if err == nil {
					t.Fatal("changed or unavailable current source accepted", mode)
				}
			})
		}
	}
}
