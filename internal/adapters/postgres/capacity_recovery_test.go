package postgres

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func TestCapacityRecoveryDecoderRetainsExactIndependentProof(t *testing.T) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	v := artifact.RecoveryProof{InstallationID: "30000000-0000-4000-8000-000000000001", IssuerEpoch: "30000000-0000-4000-8000-000000000002",
		Revision: identity.Revision{UID: "original", Generation: 1, Digest: artifact.Digest{1}}, ObservedAt: n, FreshUntil: n.Add(time.Second)}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"exact", "unknown", "duplicate", "missing", "case", "null", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			raw := bytes.Clone(b)
			switch mode {
			case "unknown":
				raw = append(raw[:len(raw)-1], []byte(`,"Trusted":true}`)...)
			case "duplicate":
				raw = append(raw[:len(raw)-1], []byte(`,"InstallationID":"30000000-0000-4000-8000-000000000001"}`)...)
			case "missing":
				raw = bytes.Replace(raw, []byte(`"Generation":1,`), nil, 1)
			case "case":
				raw = bytes.Replace(raw, []byte(`"ObservedAt":`), []byte(`"observedAt":`), 1)
			case "null":
				raw = bytes.Replace(raw, []byte(`"Revision":{`), []byte(`"Revision":null,"discarded":{`), 1)
			case "trailing":
				raw = append(raw, []byte(` {}`)...)
			}
			got, err := decodeCapacityRecovery(raw)
			if mode != "exact" {
				if err == nil {
					t.Fatal("malformed recovery snapshot accepted")
				}
				return
			}
			if err != nil || !got.Valid(n) || got.InstallationID != v.InstallationID || got.IssuerEpoch != v.IssuerEpoch || got.Revision != v.Revision || !got.ObservedAt.Equal(v.ObservedAt) || !got.FreshUntil.Equal(v.FreshUntil) || got.Valid(v.FreshUntil) {
				t.Fatal("independent recovery identity or interval changed", err)
			}
		})
	}
}
