package mtls

import (
	"context"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

type connectorObservationScopedRegistry struct {
	app.ConnectorLeafRegistry
	wanted value.ConnectorIdentitySource
	used   int
}

func (s *connectorObservationScopedRegistry) ConnectorLeafRegistrationAt(ctx context.Context, certificate value.ConnectorCredentialCertificate, source value.ConnectorIdentitySource) (app.ConnectorLeafRegistration, error) {
	s.used++
	if !source.Observation.SameSource(s.wanted.Observation) || source.Roles != s.wanted.Roles || source.Observation.ObservedAt != s.wanted.Observation.ObservedAt || source.Observation.FreshUntil != s.wanted.Observation.FreshUntil {
		return app.ConnectorLeafRegistration{}, value.ErrDenied
	}
	return s.ConnectorLeafRegistry.ConnectorLeafRegistration(ctx, certificate)
}

func TestConnectorOwnedObservationAtCarriesOriginalSourceIntoRegistration(t *testing.T) {
	f := newConnectorPairFixture(t)
	c := f.owner()
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	source, _ := f.ReadConnectorIdentitySource(context.Background())
	scoped := &connectorObservationScopedRegistry{ConnectorLeafRegistry: f, wanted: source}
	c.registry = scoped
	if _, err := c.ObserveConnectorProcessAt(context.Background(), source); err != nil || scoped.used != 1 {
		t.Fatal("nested registration did not use the executor's original source bracket", err, scoped.used)
	}
	// Ordinary observations still own their independent source reads. This
	// optimization must not silently become an ambient registration cache.
	if _, err := c.ObserveConnectorProcess(context.Background()); err != nil || scoped.used != 1 {
		t.Fatal("ordinary observation borrowed an unrelated source bracket", err, scoped.used)
	}
	f.revoked.Store(true)
	if _, err := c.ObserveConnectorProcessAt(context.Background(), source); err == nil || scoped.used != 2 {
		t.Fatal("scoped registration bypassed current revocation", err, scoped.used)
	}
}

func TestConnectorOwnedObservationRequiresActivatedCurrentOriginalProcess(t *testing.T) {
	f := newConnectorPairFixture(t)
	c := f.owner()
	if _, e := c.ObserveConnectorProcess(context.Background()); e == nil {
		t.Fatal("unadmitted process observed")
	}
	if e := c.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	o, e := c.ObserveConnectorProcess(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if o.Request.Process != o.Registration.Process || o.Registration.Certificate.Usage != "client" || !o.ValidUntil.After(f.clock()) || o.ValidUntil.After(f.clock().Add(5*time.Second)) {
		t.Fatal("unbound observation")
	}
	// Public CSR output is detached from the process-owned original.
	o.Request.ClientCSRDER[0] ^= 1
	again, e := c.ObserveConnectorProcess(context.Background())
	if e != nil || again.Request.ClientCSRDER[0] == o.Request.ClientCSRDER[0] {
		t.Fatal("caller changed owned CSR")
	}
	f.revoked.Store(true)
	if _, e = c.ObserveConnectorProcess(context.Background()); e == nil {
		t.Fatal("revoked leaf remains current")
	}
	f.revoked.Store(false)
	c.Close()
	if _, e = c.ObserveConnectorProcess(context.Background()); e == nil {
		t.Fatal("closed owner remains current")
	}
}

// ADR-199: the executor's proof checks the owned process against the source
// observation it read itself; that observation must still be this process's
// current source, and the same registration and revocation checks apply.
func TestConnectorOwnedObservationAtCallerSource(t *testing.T) {
	f := newConnectorPairFixture(t)
	c := f.owner()
	if e := c.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	source, _ := f.ReadConnectorIdentitySource(context.Background())
	o, e := c.ObserveConnectorProcessAt(context.Background(), source)
	if e != nil || o.Request.Process != o.Registration.Process || !o.Configuration.SameSource(source.Observation) {
		t.Fatal("observation at the caller's source", e)
	}
	other := source
	other.Observation.Profile = source.Observation.Profile.Clone()
	other.Observation.Profile.Binding.PeerID = "10000000-0000-4000-8000-0000000000ee"
	if _, e = c.ObserveConnectorProcessAt(context.Background(), other); e == nil {
		t.Fatal("another peer's source accepted")
	}
	stale := source
	stale.Observation.FreshUntil = f.clock()
	if _, e = c.ObserveConnectorProcessAt(context.Background(), stale); e == nil {
		t.Fatal("expired source observation accepted")
	}
	f.revoked.Store(true)
	if _, e = c.ObserveConnectorProcessAt(context.Background(), source); e == nil {
		t.Fatal("revoked leaf remains current at the caller's source")
	}
}

// ADR-199 decision 5: the executor proof's close is local. It confirms the
// opening observation's process and leaf under the closing source, never
// renews the opening registration, and refuses another source or a closed
// process.
func TestConnectorOwnedObservationConfirmIsLocalAndBounded(t *testing.T) {
	f := newConnectorPairFixture(t)
	c := f.owner()
	if e := c.Reconcile(context.Background()); e != nil {
		t.Fatal(e)
	}
	source, _ := f.ReadConnectorIdentitySource(context.Background())
	opened, e := c.ObserveConnectorProcessAt(context.Background(), source)
	if e != nil {
		t.Fatal(e)
	}
	f.revoked.Store(true) // a hub-side change is not consulted by the close
	confirmed, e := c.ConfirmConnectorProcessAt(context.Background(), opened, source)
	f.revoked.Store(false)
	if e != nil || confirmed.ObservedAt != opened.ObservedAt || confirmed.ValidUntil.After(opened.ValidUntil) || confirmed.Registration != opened.Registration || confirmed.Request.Process != opened.Request.Process {
		t.Fatal("local close", e)
	}
	changed := source
	changed.Observation.Profile = source.Observation.Profile.Clone()
	changed.Observation.Profile.Revision.Generation++
	if _, e = c.ConfirmConnectorProcessAt(context.Background(), opened, changed); e == nil {
		t.Fatal("another source revision confirmed")
	}
	c.Close()
	if _, e = c.ConfirmConnectorProcessAt(context.Background(), opened, source); e == nil {
		t.Fatal("closed process confirmed")
	}
}

func TestConnectorOwnedObservationConfirmRechecksAfterLocalVerification(t *testing.T) {
	for _, mode := range []string{"unchanged", "closed", "root-cancelled", "retired", "replaced", "new-leaf", "expired", "caller-cancelled", "shorter-caller", "caller-deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newConnectorPairFixture(t)
			c := f.owner()
			if err := c.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			source, _ := f.ReadConnectorIdentitySource(context.Background())
			opened, err := c.ObserveConnectorProcessAt(context.Background(), source)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithDeadline(context.Background(), f.now.Add(2*time.Second))
			defer cancel()
			changed := false
			// X.509 verification consults its clock after Confirm has copied the
			// active process/leaf and released c.mu. Exercise exact intervening
			// state transitions without sleeps, races or a production test hook.
			c.verifier.now = func() time.Time {
				if !changed {
					changed = true
					switch mode {
					case "closed":
						c.Close()
					case "root-cancelled":
						c.stop()
					case "retired", "replaced", "new-leaf":
						c.mu.Lock()
						switch mode {
						case "retired":
							c.active.retired = true
						case "replaced":
							replacement := *c.active
							c.active = &replacement
						case "new-leaf":
							c.active.installed[0].Digest[0] ^= 1
						}
						c.mu.Unlock()
					case "expired":
						f.advance.Store(int64(opened.ValidUntil.Sub(f.now)))
					case "caller-cancelled":
						cancel()
					case "caller-deadline":
						f.advance.Store(int64(2 * time.Second))
					}
				}
				return f.clock()
			}
			confirmed, err := c.ConfirmConnectorProcessAt(ctx, opened, source)
			if !changed {
				t.Fatal("test did not reach verification after the active snapshot")
			}
			if mode == "unchanged" || mode == "shorter-caller" {
				if err != nil || confirmed.Registration != opened.Registration || confirmed.ValidUntil.After(opened.ValidUntil) {
					t.Fatal("unchanged local confirmation", err)
				}
				if mode == "shorter-caller" && !confirmed.ValidUntil.Equal(f.now.Add(2*time.Second)) {
					t.Fatal("confirmation exceeded original caller deadline")
				}
			} else if err == nil {
				t.Fatal("local confirmation accepted a change after its active snapshot", mode)
			}
		})
	}
}
