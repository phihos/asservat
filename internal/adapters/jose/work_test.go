package jose

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	"os"
	"strings"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

type trustFunc func(context.Context, value.Receiver) (value.WorkTrust, error)

func (f trustFunc) WorkTrust(c context.Context, r value.Receiver) (value.WorkTrust, error) {
	return f(c, r)
}
func workFixture(t *testing.T) (map[string]any, value.Receiver, value.WorkTrust, ed25519.PrivateKey, time.Time) {
	t.Helper()
	b, err := os.ReadFile("../../../examples/internal-runAction.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		t.Fatal("fixture")
	}
	now := time.Date(2026, 10, 9, 12, 0, 10, 0, time.UTC)
	target := doc["target"].(map[string]any)
	r := value.Receiver{CollectorEpoch: "00000000-0000-4000-8000-000000000021", PeerID: "00000000-0000-4000-8000-000000000020", ClusterID: doc["clusterId"].(string), IssuerEpoch: doc["issuerEpoch"].(string), NodeUID: target["nodeUID"].(string), NodeBootID: target["nodeBootID"].(string), Region: "eu-central", Capabilities: []string{"control/v1"}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := value.WorkTrust{Revision: identity.Revision{UID: "work-trust", Generation: 1, Digest: [32]byte{1}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Keys: []value.WorkKey{{ID: "current", ClusterID: r.ClusterID, IssuerEpoch: r.IssuerEpoch, PublicKey: pub, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}}}
	return doc, r, trust, priv, now
}
func encodedDoc(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	v := jsontext.Value(b)
	if v.Canonicalize() != nil {
		t.Fatal("canonicalization")
	}
	return v
}
func signWork(t *testing.T, payload []byte, key ed25519.PrivateKey, alg jwa.SignatureAlgorithm, extra map[string]any) []byte {
	t.Helper()
	h := jws.NewHeaders()
	for k, v := range map[string]any{"typ": WorkType, "kid": "current"} {
		if h.Set(k, v) != nil {
			t.Fatal("header")
		}
	}
	for k, v := range extra {
		if h.Set(k, v) != nil {
			t.Fatal("extra header")
		}
	}
	b, err := jws.Sign(payload, jws.WithKey(alg, key, jws.WithProtectedHeaders(h)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func verifierFor(t *testing.T, trust value.WorkTrust, now *time.Time) *WorkVerifier {
	t.Helper()
	v, err := NewWorkVerifier(trustFunc(func(ctx context.Context, r value.Receiver) (value.WorkTrust, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded trust read")
		}
		return trust, nil
	}), func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestRunActionSignatureRoundTripAndRotation(t *testing.T) {
	doc, receiver, trust, priv, now := workFixture(t)
	signed := signWork(t, encodedDoc(t, doc), priv, jwa.EdDSAEd25519(), nil)
	v := verifierFor(t, trust, &now)
	r, err := v.VerifyRunAction(context.Background(), signed, receiver)
	if err != nil {
		t.Fatal(err)
	}
	if r.KeyID != "current" || r.Work.AttemptID != doc["payload"].(map[string]any)["attemptId"] || !r.ValidUntil.Equal(trust.FreshUntil) {
		t.Fatal("identity or original cutoff lost")
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust.Keys[0].PublicKey = pub
	trust.Revision.Generation++
	if _, err = verifierFor(t, trust, &now).VerifyRunAction(context.Background(), signed, receiver); err == nil {
		t.Fatal("replacement key authenticated old work")
	}
	trust.Keys[0].PublicKey = priv.Public().(ed25519.PublicKey)
	trust.Keys[0].NotAfter = now.Add(10 * time.Second)
	if _, err = verifierFor(t, trust, &now).VerifyRunAction(context.Background(), signed, receiver); err == nil {
		t.Fatal("work outlives signing key")
	}
}
func TestRunActionRejectsValidlySignedWrongWork(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any, *value.Receiver, *value.WorkTrust, *time.Time)
	}{
		{"wrong-cluster", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["clusterId"] = "00000000-0000-4000-8000-000000000099"
		}},
		{"wrong-epoch", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["issuerEpoch"] = "00000000-0000-4000-8000-000000000099"
		}},
		{"wrong-boot", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["target"].(map[string]any)["nodeBootID"] = "00000000-0000-4000-8000-000000000099"
		}},
		{"wrong-node", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["target"].(map[string]any)["nodeUID"] = "00000000-0000-4000-8000-000000000099"
		}},
		{"non-utc-issuance", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["issuedAt"] = "2026-10-09T14:00:00+02:00"
		}},
		{"noncanonical-fraction", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["notAfter"] = "2026-10-09T12:00:45.000Z"
		}},
		{"non-utc-reference", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["auditRef"].(map[string]any)["expiresAt"] = "2026-10-09T14:01:00+02:00"
		}},

		{"expired-work", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["notAfter"] = "2026-10-09T12:00:10Z"
		}},
		{"future-issuance", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["issuedAt"] = "2026-10-09T12:00:11Z"
		}},
		{"overlong-permit", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["notAfter"] = "2026-10-09T12:01:01Z"
		}},
		{"fractional-fence", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) { d["deliveryFence"] = 1.5 }},
		{"unsafe-integer", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["deliveryFence"] = float64(9007199254740992)
		}},
		{"command-in-payload", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["payload"].(map[string]any)["command"] = "touch /host"
		}},
		{"case-alias", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["ClusterId"] = d["clusterId"]
			delete(d, "clusterId")
		}},
		{"wrong-scope-reference", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["scopeRef"].(map[string]any)["digest"] = strings.Repeat("b", 64)
		}},
		{"reference-expiry", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["budgetRef"].(map[string]any)["expiresAt"] = "2026-10-09T12:00:20Z"
		}},
		{"reference-region", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["auditRef"].(map[string]any)["region"] = "elsewhere"
		}},
		{"unsupported-capability", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["requiredCapabilities"] = []string{"arbitrary/commands"}
		}},
		{"duplicate-capability", func(d map[string]any, _ *value.Receiver, _ *value.WorkTrust, _ *time.Time) {
			d["requiredCapabilities"] = []string{"control/v1", "control/v1"}
		}},
		{"stale-peer", func(_ map[string]any, r *value.Receiver, _ *value.WorkTrust, n *time.Time) { r.ValidUntil = *n }},
		{"stale-trust", func(_ map[string]any, _ *value.Receiver, k *value.WorkTrust, n *time.Time) { k.FreshUntil = *n }},
		{"duplicate-kid", func(_ map[string]any, _ *value.Receiver, k *value.WorkTrust, _ *time.Time) {
			k.Keys = append(k.Keys, k.Keys[0])
		}},
		{"key-wrong-cluster", func(_ map[string]any, _ *value.Receiver, k *value.WorkTrust, _ *time.Time) {
			k.Keys[0].ClusterID = "00000000-0000-4000-8000-000000000099"
		}},
		{"key-wrong-epoch", func(_ map[string]any, _ *value.Receiver, k *value.WorkTrust, _ *time.Time) {
			k.Keys[0].IssuerEpoch = "00000000-0000-4000-8000-000000000099"
		}},
		{"key-not-yet-active", func(_ map[string]any, _ *value.Receiver, k *value.WorkTrust, n *time.Time) {
			k.Keys[0].NotBefore = n.Add(time.Second)
		}},
		{"key-invalid-length", func(_ map[string]any, _ *value.Receiver, k *value.WorkTrust, _ *time.Time) {
			k.Keys[0].PublicKey = k.Keys[0].PublicKey[:31]
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d, r, k, priv, n := workFixture(t)
			test.mutate(d, &r, &k, &n)
			signed := signWork(t, encodedDoc(t, d), priv, jwa.EdDSAEd25519(), nil)
			if _, err := verifierFor(t, k, &n).VerifyRunAction(context.Background(), signed, r); err == nil {
				t.Fatal("unsafe work accepted")
			}
		})
	}
}
func TestRunActionRejectsJWSConfusionAndMalformedPayload(t *testing.T) {
	doc, r, k, priv, n := workFixture(t)
	v := verifierFor(t, k, &n)
	payload := encodedDoc(t, doc)
	for name, headers := range map[string]map[string]any{"wrong-type": {"typ": "JWT"}, "untrusted-kid": {"kid": "unknown"}, "remote-key": {"jku": "https://outside.invalid/keys"}, "critical": {"crit": []string{"custom"}, "custom": "x"}} {
		t.Run(name, func(t *testing.T) {
			signed := signWork(t, payload, priv, jwa.EdDSAEd25519(), headers)
			if _, err := v.VerifyRunAction(context.Background(), signed, r); err == nil {
				t.Fatal("unsafe header accepted")
			}
		})
	}
	legacy := signWork(t, payload, priv, jwa.EdDSA(), nil)
	if _, err := v.VerifyRunAction(context.Background(), legacy, r); err == nil {
		t.Fatal("polymorphic EdDSA downgrade")
	}
	for name, b := range map[string][]byte{"noncanonical": append([]byte(" "), payload...), "duplicate": append([]byte(`{"purpose":"runAction",`), payload[1:]...), "trailing": append(append([]byte{}, payload...), []byte("{}")...), "invalid-unicode": []byte("{\"x\":\"\xff\"}"), "too-deep": []byte(strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33))} {
		t.Run(name, func(t *testing.T) {
			signed := signWork(t, b, priv, jwa.EdDSAEd25519(), nil)
			if _, err := v.VerifyRunAction(context.Background(), signed, r); err == nil {
				t.Fatal("unsafe signed payload accepted")
			}
		})
	}
	signed := signWork(t, payload, priv, jwa.EdDSAEd25519(), nil)
	parts := strings.Split(string(signed), ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	if _, err := v.VerifyRunAction(context.Background(), []byte(strings.Join(parts, ".")), r); err == nil {
		t.Fatal("tampering accepted")
	}
	parts = strings.Split(string(signed), ".")
	parts[0] += "="
	if _, err := v.VerifyRunAction(context.Background(), []byte(strings.Join(parts, ".")), r); err == nil {
		t.Fatal("noncanonical base64 accepted")
	}
	if _, err := v.VerifyRunAction(context.Background(), make([]byte, MaxSignedWork+1), r); err == nil {
		t.Fatal("oversize envelope accepted")
	}
}
func TestRunActionTrustReadDoesNotExtendFreshness(t *testing.T) {
	d, r, k, priv, n := workFixture(t)
	signed := signWork(t, encodedDoc(t, d), priv, jwa.EdDSAEd25519(), nil)
	v, err := NewWorkVerifier(trustFunc(func(context.Context, value.Receiver) (value.WorkTrust, error) { n = k.FreshUntil; return k, nil }), func() time.Time { return n })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.VerifyRunAction(context.Background(), signed, r); err == nil {
		t.Fatal("trust read freshened expired snapshot")
	}
}
