package contracts

import (
	"errors"
	"testing"
)

// ADR-196 decision 7: the offer names the whole executor section or none.
func TestRegionalExecutorOfferedWholeOrNone(t *testing.T) {
	full := RegionalOffer{Owners: &RegionalContextOwners{}, KeyService: &RegionalWrapService{}, WorkKey: &APIContextWorkPublicKey{}, EvidenceStore: &RegionalEvidenceStore{}}
	if executor, err := full.RegionalExecutorOffered(); err != nil || !executor {
		t.Fatal("complete section", executor, err)
	}
	if executor, err := (RegionalOffer{}).RegionalExecutorOffered(); err != nil || executor {
		t.Fatal("plain connector", executor, err)
	}
	partial := full
	partial.WorkKey = nil
	if _, err := partial.RegionalExecutorOffered(); !errors.Is(err, ErrRegionalOfferPartial) {
		t.Fatal("partial section accepted", err)
	}
}
