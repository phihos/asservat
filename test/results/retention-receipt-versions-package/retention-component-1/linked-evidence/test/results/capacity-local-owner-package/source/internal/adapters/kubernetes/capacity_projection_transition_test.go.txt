package kubernetes

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestCapacityProjectionCASCannotRewriteSiblingOrOriginal(t *testing.T) {
	for _, mode := range []string{"claim", "complete", "claim-with-receipt", "same-pending", "receipt-rewrite", "change-interval", "change-setup", "drop-object", "change-binding", "add-cleanup", "delete-claim"} {
		t.Run(mode, func(t *testing.T) {
			_, v, _ := capacityProjectionStateFixture()
			v.CleanupProjection = &contracts.CaptureCleanupProjectionClaim{OperationID: ownerID(2300), Setup: v.CapacityProjection.Setup}
			raw, _ := json.Marshal(v)
			var next contracts.InitialRuntimeResourceState
			if json.Unmarshal(raw, &next) != nil {
				t.Fatal("synthetic state encoding")
			}
			v.CapacityProjection.Receipt = nil
			switch mode {
			case "claim":
				v.CapacityProjection = nil
				next.CapacityProjection.Receipt = nil
			case "complete":
			case "claim-with-receipt":
				v.CapacityProjection = nil
			case "same-pending":
				next.CapacityProjection.Receipt = nil
			case "receipt-rewrite":
				c := *next.CapacityProjection.Receipt
				v.CapacityProjection.Receipt = &c
				next.CapacityProjection.Receipt.ResourceVersion = "replacement"
			case "change-interval":
				next.CapacityProjection.Until = next.CapacityProjection.Until.Add(time.Microsecond)
			case "change-setup":
				next.CapacityProjection.Setup.DatabaseOID++
			case "drop-object":
				next.Objects = next.Objects[:len(next.Objects)-1]
			case "change-binding":
				next.BindingDigest = "changed"
			case "add-cleanup":
				next.CleanupProjection.OperationID = ownerID(2301)
			case "delete-claim":
				next.CapacityProjection = nil
			}
			if capacityProjectionTransition(v, next) != (mode == "claim" || mode == "complete") {
				t.Fatal("capacity-only CAS boundary differs", mode)
			}
		})
	}
}
