package kubernetes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func witnessTestClaim() value.InitialActivationClaim {
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	return value.InitialActivationClaim{ID: "11111111-1111-4111-8111-111111111111", Database: value.DatabaseIncarnation{StartedAt: now.Add(-time.Minute), DatabaseOID: 16384, SchemaVersion: 31}, FleetSource: identity.Revision{UID: "fleet-source", Generation: 1, Digest: [32]byte{1}}, PlanDigest: artifact.Digest{1}, NotBefore: now, NotAfter: now.Add(time.Minute)}
}

func TestInitialWitnessClosedWireAndBounds(t *testing.T) {
	v, err := newPermissionValidator()
	if err != nil {
		t.Fatal(err)
	}
	c := witnessTestClaim()
	w := contracts.InstallationWitness{SchemaVersion: "installation-witness/v1", InstallationID: c.ID, IssuerEpoch: c.ID, WriterAccountUID: c.ID, Claim: witnessClaimWire(c)}
	for _, mode := range []string{"fresh", "consumed", "unknown", "case-alias", "duplicate", "bad-key", "zero-oid", "expired-window", "submicrosecond", "database-after-claim", "noncanonical-time"} {
		t.Run(mode, func(t *testing.T) {
			copy := w
			inner := *w.Claim
			copy.Claim = &inner
			switch mode {
			case "fresh":
				copy.Claim = nil
			case "bad-key":
				copy.Claim.PlanDigest = strings.Repeat("0", 64)
			case "zero-oid":
				copy.Claim.DatabaseOID = 0
			case "expired-window":
				copy.Claim.NotAfter = c.NotBefore.Add(5*time.Minute + time.Microsecond).Format(time.RFC3339Nano)
			case "submicrosecond":
				copy.Claim.DatabaseStart = c.Database.StartedAt.Add(time.Nanosecond).Format(time.RFC3339Nano)
			case "database-after-claim":
				copy.Claim.DatabaseStart = c.NotAfter.Format(time.RFC3339Nano)
			case "noncanonical-time":
				copy.Claim.NotBefore = strings.TrimSuffix(copy.Claim.NotBefore, "Z") + "+00:00"
			}
			raw, _ := json.Marshal(copy)
			switch mode {
			case "unknown":
				raw = append([]byte(`{"reset":true,`), raw[1:]...)
			case "case-alias":
				raw = []byte(strings.Replace(string(raw), `"installationID"`, `"InstallationID"`, 1))
			case "duplicate":
				raw = append([]byte(`{"claim":null,`), raw[1:]...)
			}
			var decoded contracts.InstallationWitness
			_, err := decodePermissionSpec(raw, v.witnessSchema, &decoded)
			var restored *value.InitialActivationClaim
			if err == nil {
				restored, err = witnessClaimValue(decoded.Claim)
			}
			valid := mode == "fresh" || mode == "consumed"
			if (err == nil) != valid {
				t.Fatal("unexpected witness acceptance", mode, err)
			}
			if mode == "consumed" && (restored == nil || *restored != c) {
				t.Fatal("consumption changed, including equal source/plan digests")
			}
		})
	}
	if !c.Current(c.NotBefore) || c.Current(c.NotAfter) || c.Current(c.NotBefore.Add(-time.Microsecond)) {
		t.Fatal("claim deadline is not an original half-open interval")
	}
}
