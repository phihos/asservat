package fleet

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"slices"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
)

const ConnectorRetirementTicketBytes = 16 << 10
const ConnectorRetirementSetLimit = 4096
const connectorRetirementTicketDomain = "asservat-connector-retirement-ticket/v1\x00"
const connectorRetirementSetDomain = "asservat-connector-retirement-set/v1\x00"

// CanonicalConnectorRetirementTicket fixes UTC/microsecond JSON bytes once for
// the immutable SQL row. PostgreSQL hashes those retained bytes, not jsonb::text
// (whose rendering is not our protocol). The row guard independently compares
// the decoded typed fields to exact accepted source/backing/actor facts.
func CanonicalConnectorRetirementTicket(ticket audit.ConnectorRetirementTicket) ([]byte, artifact.Digest, error) {
	if !ticket.Valid() {
		return nil, artifact.Digest{}, value.ErrUnavailable
	}
	t := ticket.Clone()
	t.ReservedAt = t.ReservedAt.UTC()
	t.AdmissionUntil = t.AdmissionUntil.UTC()
	t.ConsumeUntil = t.ConsumeUntil.UTC()
	t.RetainUntil = t.RetainUntil.UTC()
	t.OriginalAcceptancePurgeAt = t.OriginalAcceptancePurgeAt.UTC()
	t.Policy.ValidUntil = t.Policy.ValidUntil.UTC()
	b, e := json.Marshal(t)
	if e != nil || len(b) > ConnectorRetirementTicketBytes {
		return nil, artifact.Digest{}, value.ErrUnavailable
	}
	h := sha256.New()
	_, _ = h.Write([]byte(connectorRetirementTicketDomain))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
	var d artifact.Digest
	copy(d[:], h.Sum(nil))
	return b, d, nil
}

func ReadCanonicalConnectorRetirementTicket(b []byte) (audit.ConnectorRetirementTicket, error) {
	var t audit.ConnectorRetirementTicket
	if len(b) == 0 || len(b) > ConnectorRetirementTicketBytes || json.Unmarshal(b, &t) != nil {
		return t, value.ErrUnavailable
	}
	canonical, _, e := CanonicalConnectorRetirementTicket(t)
	if e != nil || !bytes.Equal(canonical, b) {
		return audit.ConnectorRetirementTicket{}, value.ErrUnavailable
	}
	return t, nil
}

// ConnectorRetirementSetDigest binds a complete exact immutable set before
// acknowledgement/promotion. SQL must independently repeat this computation over
// its retained rows and compare count, never trust the caller's digest alone.
// There is exactly one ticket per logical peer in one acceptance/backing set.
func ConnectorRetirementSetDigest(tickets []audit.ConnectorRetirementTicket) (artifact.Digest, error) {
	if len(tickets) < 1 || len(tickets) > ConnectorRetirementSetLimit {
		return artifact.Digest{}, value.ErrUnavailable
	}
	tickets = slices.Clone(tickets)
	slices.SortFunc(tickets, func(a, b audit.ConnectorRetirementTicket) int {
		return bytes.Compare([]byte(a.Binding.PeerID), []byte(b.Binding.PeerID))
	})
	h := sha256.New()
	_, _ = h.Write([]byte(connectorRetirementSetDomain))
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(tickets)))
	_, _ = h.Write(count[:])
	first := tickets[0]
	seen := make(map[string]bool, len(tickets))
	for i, t := range tickets {
		if seen[t.ID] || i > 0 && tickets[i-1].Binding.PeerID == t.Binding.PeerID || t.RootID != first.RootID || t.AcceptanceID != first.AcceptanceID || t.OriginalActor != first.OriginalActor || !t.ReservedAt.Equal(first.ReservedAt) || !t.AdmissionUntil.Equal(first.AdmissionUntil) || !t.RetainUntil.Equal(first.RetainUntil) || !t.OriginalAcceptancePurgeAt.Equal(first.OriginalAcceptancePurgeAt) || t.AccountVersion != first.AccountVersion || t.BackingRevision != first.BackingRevision || t.BackingDigest != first.BackingDigest || !audit.CompatibleConnectorPolicy(t.Policy, first.Policy) {
			return artifact.Digest{}, value.ErrUnavailable
		}
		_, d, e := CanonicalConnectorRetirementTicket(t)
		if e != nil {
			return artifact.Digest{}, e
		}
		seen[t.ID] = true
		_, _ = h.Write(d[:])
	}
	var result artifact.Digest
	copy(result[:], h.Sum(nil))
	return result, nil
}
