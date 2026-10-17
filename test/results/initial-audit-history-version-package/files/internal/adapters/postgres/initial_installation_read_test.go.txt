package postgres

import (
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestInitialInstallationHistoricalObservation(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	n := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	scope := value.InstallationWitnessScope{InstallationID: id, IssuerEpoch: id, ClusterID: id, Namespace: "control", NamespaceUID: id, Name: "witness", UID: id, WriterAccount: "installer", WriterAccountUID: id}
	r := audit.InitialInstallation{Scope: scope, Claim: value.InitialActivationClaim{ID: id, Database: value.DatabaseIncarnation{StartedAt: n.Add(-time.Hour), DatabaseOID: 1, SchemaVersion: 32}, FleetSource: identity.Revision{UID: "source", Generation: 1, Digest: artifact.Digest{1}}, PlanDigest: artifact.Digest{2}, NotBefore: n, NotAfter: n.Add(5 * time.Minute)}}
	b, _ := json.Marshal(r)
	receipt := audit.Receipt{Key: audit.InitialInstallationKey(id, id), Version: "original-version", ETag: "synthetic", Bytes: 32, SHA256: artifact.Digest{3}}
	ack, _ := json.Marshal(receipt)
	missingVersion := receipt
	missingVersion.Version = ""
	missingAck, _ := json.Marshal(missingVersion)
	nullVersion := receipt
	nullVersion.Version = "null"
	nullAck, _ := json.Marshal(nullVersion)
	for _, test := range []struct {
		name         string
		raw, receipt []byte
		at           pgtype.Timestamptz
		want         app.InitialInstallationDisposition
	}{
		{"prepared", b, nil, pgtype.Timestamptz{}, app.InitialInstallationPrepared},
		{"audited", b, ack, pgtype.Timestamptz{}, app.InitialInstallationAudited},
		{"expired-claim-historical-success", b, ack, ts(n.Add(time.Second)), app.InitialInstallationActivated},
		{"unversioned-audited-history", b, missingAck, pgtype.Timestamptz{}, ""},
		{"unversioned-activated-history", b, missingAck, ts(n.Add(time.Second)), ""},
		{"null-version-audited-history", b, nullAck, pgtype.Timestamptz{}, ""},
		{"null-version-activated-history", b, nullAck, ts(n.Add(time.Second)), ""},
		{"activation-without-audit", b, nil, ts(n.Add(time.Second)), ""},
		{"activation-at-expiry", b, ack, ts(r.Claim.NotAfter), ""},
		{"activation-before-claim", b, ack, ts(n.Add(-time.Second)), ""},
		{"unknown-record-field", append(append([]byte(nil), b[:len(b)-1]...), []byte(`,"Extra":true}`)...), ack, pgtype.Timestamptz{}, ""},
		{"trailing-record", append(append([]byte(nil), b...), []byte(` {}`)...), ack, pgtype.Timestamptz{}, ""},
		{"foreign-audit", b, []byte(`{"Key":"foreign"}`), pgtype.Timestamptz{}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := initialInstallationObservation(test.raw, test.receipt, test.at, scope, r.Claim.PlanDigest)
			if test.want == "" {
				if err == nil {
					t.Fatal("invalid historical state accepted")
				}
				return
			}
			if err != nil || got.Disposition != test.want || !got.Record.Claim.Same(r.Claim) || !got.ValidUntil.IsZero() {
				t.Fatal("historical observation", err)
			}
		})
	}
	other := scope
	other.UID = "22222222-2222-4222-8222-222222222222"
	if _, err := initialInstallationObservation(b, ack, ts(n.Add(time.Second)), other, r.Claim.PlanDigest); err == nil {
		t.Fatal("foreign witness accepted")
	}
	if _, err := initialInstallationObservation(b, ack, ts(n.Add(time.Second)), scope, artifact.Digest{9}); err == nil {
		t.Fatal("foreign startup plan accepted")
	}
}
