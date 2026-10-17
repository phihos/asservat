package mtls

import (
	"context"
	"testing"
	"time"
)

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
