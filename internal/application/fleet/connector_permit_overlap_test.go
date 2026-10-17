package fleet

import (
	"context"
	"testing"
	"time"
)

// Current proof/source reads finish after the immutable request start in an
// actual operation. Advancing this synthetic clock makes that order explicit.
func TestConnectorIssuanceAcceptsSequentialOriginalObservations(t *testing.T) {
	for _, usage := range []string{"client", "server"} {
		t.Run(usage, func(t *testing.T) {
			f, _, s := newConnectorProcessFixture(t)
			start := f.now
			f.proofHook = func(f *connectorProcessFixture) { f.now = f.now.Add(time.Millisecond) }
			f.sourceHook = func(f *connectorRenewalFixture) { f.now = f.now.Add(time.Millisecond) }
			out, err := s.IssueProcess(context.Background(), f.connectorRenewalFixture.request.ID, usage, f.request)
			if err != nil || out.Certificate.Usage != usage || f.signs != 1 || f.activations != 1 {
				t.Fatalf("overlapping sequential observations rejected: %v; signs=%d activations=%d", err, f.signs, f.activations)
			}
			p := f.row.Permit
			if !p.CheckedAt.Equal(start) || !p.SignBefore.Equal(start.Add(5*time.Second)) || !f.providerDeadline.Equal(p.SignBefore) || !f.row.Intent.CreatedAt.Equal(start) {
				t.Fatal("historical validation changed original request, audit, or provider bounds")
			}
			if p.Valid(p.SignBefore) {
				t.Fatal("historical overlap renewed current signing authority")
			}
			// A later current request may reconcile this exact activated result;
			// it cannot sign again or rewrite its original observations.
			f.now = start.Add(6 * time.Second)
			if _, err = s.IssueProcess(context.Background(), f.connectorRenewalFixture.request.ID, usage, f.request); err != nil || f.signs != 1 || !f.row.Permit.CheckedAt.Equal(start) {
				t.Fatal("stored exact result failed current reconciliation or signed again", err, f.signs)
			}
		})
	}
}

func TestConnectorIssuanceStopsWhenSequentialProofCrossesOriginalEnd(t *testing.T) {
	f, _, s := newConnectorProcessFixture(t)
	f.proofHook = func(f *connectorProcessFixture) { f.now = f.now.Add(6 * time.Second) }
	if _, err := s.IssueProcess(context.Background(), f.connectorRenewalFixture.request.ID, "client", f.request); err == nil || f.signs != 0 || f.claims != 0 || f.row != nil {
		t.Fatal("detached current proof reached admission or signing", err)
	}
}
