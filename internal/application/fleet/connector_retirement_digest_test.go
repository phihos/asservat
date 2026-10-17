package fleet

import (
	"bytes"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/audit"
)

func TestConnectorRetirementCanonicalSetRejectsSubstitutionAndDuplicates(t *testing.T) {
	plan := connectorTicketPlan(t)
	a, e := plan.Ticket()
	if e != nil {
		t.Fatal(e)
	}
	b := a.Clone()
	b.ID = "27000000-0000-4000-8000-000000000008"
	b.Policy.PolicyID = b.ID
	b.Policy.PolicyDigest[0]++
	b.Binding.PeerID = "27000000-0000-4000-8000-000000000009"
	b.Binding.ClusterID = "27000000-0000-4000-8000-000000000010"
	b.PrincipalDigest[0]++
	b.Behavior.UID = "27000000-0000-4000-8000-000000000011"
	if !b.Valid() {
		t.Fatal("distinct peer ticket rejected")
	}
	first, e := ConnectorRetirementSetDigest([]audit.ConnectorRetirementTicket{a, b})
	reverse, e2 := ConnectorRetirementSetDigest([]audit.ConnectorRetirementTicket{b, a})
	if e != nil || e2 != nil || first != reverse {
		t.Fatal("set depended on query order", e, e2)
	}
	for _, field := range []string{"duplicate peer", "duplicate ticket", "different acceptance", "different actor", "different backing", "different resource"} {
		t.Run(field, func(t *testing.T) {
			changed := b.Clone()
			switch field {
			case "duplicate peer":
				changed.Binding.PeerID = a.Binding.PeerID
			case "duplicate ticket":
				changed.ID = a.ID
				changed.Policy.PolicyID = a.ID
			case "different acceptance":
				changed.AcceptanceID = changed.ID
			case "different actor":
				changed.OriginalActor.Process.ProcessEpoch = changed.ID
			case "different backing":
				changed.BackingDigest[0]++
			case "different resource":
				changed.Policy.StoreID = changed.ID
			}
			if _, e := ConnectorRetirementSetDigest([]audit.ConnectorRetirementTicket{a, changed}); e == nil {
				t.Fatal("changed set accepted")
			}
		})
	}
	one, e := ConnectorRetirementSetDigest([]audit.ConnectorRetirementTicket{a})
	if e != nil || one == first {
		t.Fatal("count not bound", e)
	}
	changed := b.Clone()
	changed.Behavior.Digest[0]++
	other, e := ConnectorRetirementSetDigest([]audit.ConnectorRetirementTicket{a, changed})
	if e != nil || other == first {
		t.Fatal("behavior omitted from immutable set", e)
	}
}

func TestConnectorRetirementTicketCanonicalBytesAreStableAndStrict(t *testing.T) {
	p := connectorTicketPlan(t)
	ticket, e := p.Ticket()
	if e != nil {
		t.Fatal(e)
	}
	b, d, e := CanonicalConnectorRetirementTicket(ticket)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := ReadCanonicalConnectorRetirementTicket(b)
	if e != nil || !decoded.Valid() {
		t.Fatal("canonical ticket failed round trip", e)
	}
	// Same instants under another offset normalize to the same original bytes.
	zone := time.FixedZone("test", 7200)
	ticket.ReservedAt = ticket.ReservedAt.In(zone)
	ticket.Policy.ValidUntil = ticket.Policy.ValidUntil.In(zone)
	b2, d2, e := CanonicalConnectorRetirementTicket(ticket)
	if e != nil || !bytes.Equal(b, b2) || d != d2 {
		t.Fatal("timezone changed ticket identity", e)
	}
	for _, bad := range [][]byte{append([]byte(" "), b...), append(b[:len(b)-1:len(b)-1], []byte(",\"extra\":true}")...)} {
		if _, e := ReadCanonicalConnectorRetirementTicket(bad); e == nil {
			t.Fatal("noncanonical or unknown ticket fields accepted")
		}
	}
	if _, e := ConnectorRetirementSetDigest(nil); e == nil {
		t.Fatal("empty set accepted")
	}
	if _, e := ConnectorRetirementSetDigest(make([]audit.ConnectorRetirementTicket, ConnectorRetirementSetLimit+1)); e == nil {
		t.Fatal("unbounded set accepted")
	}
}
