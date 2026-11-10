package integration

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/transport/browser"
	"github.com/jackc/pgx/v5/pgxpool"
)

// qualifyInstalledFleetIssuance exercises the installed ADR-193 issuance host,
// including the installer's provider role, protected settings and compiled SQL
// grants. Fixture administration only reads the resulting SQL and operator KV
// channel; it does not supply authority, issue a token or activate a slot.
func qualifyInstalledFleetIssuance(t *testing.T, ctx context.Context, sql *pgxpool.Pool, identity *installedIdentity, publicRoot []byte, address, origin, installation, mount string, providers *initialRuntimeNativeProviders) {
	t.Helper()
	root, err := x509.ParseCertificate(publicRoot)
	if err != nil || identity == nil {
		t.Fatal("installed fleet issuance requires the public root and actual browser identity")
	}
	b := identity.consoleSession(t, ctx, root, address, origin)
	const profile = "regional-installer"
	const key = "installed-fleet-bootstrap-0001"
	type reply struct {
		BootstrapID       string    `json:"bootstrapID"`
		ClusterID         string    `json:"clusterID"`
		PeerID            string    `json:"peerID"`
		IssuerEpoch       string    `json:"issuerEpoch"`
		DeliveryProfile   string    `json:"deliveryProfile"`
		CredentialVersion int       `json:"credentialVersion"`
		NotBefore         time.Time `json:"notBefore"`
		NotAfter          time.Time `json:"notAfter"`
	}
	issue := func() reply {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, b.base+browser.FleetBootstrapPath,
			bytes.NewBufferString(`{"displayName":"installed public issuance","region":"eu-test","deliveryProfile":"regional-installer"}`))
		if err != nil {
			t.Fatal("installed fleet request", err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", b.base)
		request.Header.Set("X-CSRF-Token", b.csrf)
		request.Header.Set("Idempotency-Key", key)
		response, err := b.client.Do(request)
		if err != nil {
			t.Fatal("installed fleet HTTP", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			t.Fatal("installed fleet issuance HTTP status", response.StatusCode)
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
		if err != nil || len(raw) > 4096 {
			t.Fatal("installed fleet receipt size/read")
		}
		var out reply
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields() // the public receipt must contain no secret
		if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF ||
			!authorization.UUID(out.BootstrapID) || !authorization.UUID(out.ClusterID) || !authorization.UUID(out.PeerID) || !authorization.UUID(out.IssuerEpoch) ||
			out.DeliveryProfile != profile || out.CredentialVersion != 1 || out.NotBefore.IsZero() || !out.NotAfter.After(out.NotBefore) || out.NotAfter.Sub(out.NotBefore) > 5*time.Minute {
			t.Fatal("installed fleet public receipt contract")
		}
		return out
	}
	count := func() int {
		t.Helper()
		var n int
		if err := sql.QueryRow(ctx, `SELECT count(*) FROM fleet_bootstrap_intent WHERE installation_id=$1`, installation).Scan(&n); err != nil {
			t.Fatal("installed fleet intent count", err)
		}
		return n
	}
	before := count()
	first := issue()
	if count() != before+1 {
		t.Fatal("installed fleet issuance did not reserve exactly one intent")
	}
	// Read the actual runtime's completed effect through an independent observer.
	// Whole-row snapshots also bind every immutable receipt and original deadline
	// across replay, without copying secret bytes into test logs.
	snapshot := func() (string, string) {
		t.Helper()
		var intent, token string
		if err := sql.QueryRow(ctx, `SELECT to_jsonb(i)::text,to_jsonb(b)::text
			FROM fleet_bootstrap_intent i JOIN fleet_bootstrap b USING(installation_id,id)
			WHERE i.installation_id=$1 AND i.id=$2 AND i.issued_at IS NOT NULL AND i.audit_acknowledged_at IS NOT NULL
			AND i.audit_object_key=$3 AND i.credential_version=1 AND i.credential_sha256=b.secret_sha256
			AND i.audit_object_version=b.issue_audit_version AND NOT b.revoked AND b.claimed_at IS NULL`,
			installation, first.BootstrapID, "bootstrap-issue/v1/"+installation+"/"+first.BootstrapID+"/record").Scan(&intent, &token); err != nil {
			t.Fatal("installed fleet acknowledged audit and claimable slot", err)
		}
		return intent, token
	}
	intent, token := snapshot()
	if again := issue(); again != first || count() != before+1 {
		t.Fatal("installed fleet replay changed the original public slot or reserved another intent")
	}
	if nextIntent, nextToken := snapshot(); nextIntent != intent || nextToken != token {
		t.Fatal("installed fleet replay changed a persisted receipt or original bound")
	}
	// The fleet operator reads the configured channel separately, as the regional
	// installer does. Its strict product decoder checks the private record shape.
	raw := providers.admin(t, ctx, http.MethodGet, mount+"/data/connector/"+installation+"/"+first.BootstrapID, nil, http.StatusOK)
	defer clear(raw)
	var stored struct {
		Data struct {
			Data     json.RawMessage `json:"data"`
			Metadata struct {
				Version   int  `json:"version"`
				Destroyed bool `json:"destroyed"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &stored) != nil || stored.Data.Metadata.Version != 1 || stored.Data.Metadata.Destroyed {
		t.Fatal("installed fleet operator channel version")
	}
	defer clear(stored.Data.Data)
	envelope, err := kms.DecodeBootstrapRecord(stored.Data.Data)
	if err != nil || envelope.BootstrapID != first.BootstrapID || envelope.Binding.InstallationID != installation || envelope.Binding.ClusterID != first.ClusterID ||
		envelope.Binding.PeerID != first.PeerID || envelope.Binding.IssuerEpoch != first.IssuerEpoch || envelope.DeliveryProfile != first.DeliveryProfile ||
		!envelope.NotBefore.Equal(first.NotBefore) || !envelope.NotAfter.Equal(first.NotAfter) {
		t.Fatal("installed fleet channel did not preserve the issued binding and original deadline")
	}
	digest, err := mtls.BootstrapDigest(installation, envelope.BootstrapID, envelope.Secret)
	if err != nil {
		t.Fatal("installed fleet channel secret format")
	}
	var matches bool
	if err := sql.QueryRow(ctx, `SELECT i.credential_sha256=$3 AND i.request_digest=$4
		AND i.cluster_id=$5 AND i.peer_id=$6 AND i.issuer_epoch=$7 AND i.not_before=$8 AND i.not_after=$9
		FROM fleet_bootstrap_intent i WHERE i.installation_id=$1 AND i.id=$2`,
		installation, first.BootstrapID, digest[:], envelope.RequestDigest[:], first.ClusterID, first.PeerID, first.IssuerEpoch, first.NotBefore, first.NotAfter).Scan(&matches); err != nil || !matches {
		t.Fatal("installed fleet channel credential did not match the issued SQL binding", err)
	}
	t.Log("installed fleet issuance: authenticated browser returned one audited slot; replay kept all receipts and bounds; operator KV held the matching version-1 credential")
}
